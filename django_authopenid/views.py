# -*- coding: utf-8 -*-
# Copyright 2007, 2008,2009 by Benoît Chesneau <benoitc@e-engura.org>
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required

from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response as render
from django.template import RequestContext, loader, Context


from django.core.urlresolvers import reverse
from django.utils.encoding import smart_unicode
from django.utils.translation import ugettext as _
from django.contrib.sites.models import Site
from django.utils.http import urlquote_plus
from django.core.mail import send_mail

from openid.consumer.consumer import Consumer, \
    SUCCESS, CANCEL, FAILURE, SETUP_NEEDED
from openid.consumer.discover import DiscoveryFailure
from openid.extensions import sreg
# needed for some linux distributions like debian
try:
    from openid.yadis import xri
except ImportError:
    from yadis import xri

import re
import urllib

from django_authopenid import DjangoOpenIDStore
from django_authopenid.forms import *
from django_authopenid.models import UserAssociation, UserPasswordQueue
from django_authopenid.utils import *

def ask_openid(request, openid_url, redirect_to, on_failure=None,
        sreg_request=None):
    """ basic function to ask openid and return response """
    on_failure = on_failure or signin_failure
    
    trust_root = getattr(
        settings, 'OPENID_TRUST_ROOT', get_url_host(request) + '/'
    )
    if xri.identifierScheme(openid_url) == 'XRI' and getattr(
            settings, 'OPENID_DISALLOW_INAMES', False
    ):
        msg = _("i-names are not supported")
        return on_failure(request, msg)
    consumer = Consumer(request.session, DjangoOpenIDStore())
    try:
        auth_request = consumer.begin(openid_url)
    except DiscoveryFailure:
        msg = _("The OpenID %s was invalid" % openid_url)
        return on_failure(request, msg)

    if sreg_request:
        auth_request.addExtension(sreg_request)
    redirect_url = auth_request.redirectURL(trust_root, redirect_to)
    return HttpResponseRedirect(redirect_url)

def complete(request, on_success=None, on_failure=None, return_to=None):
    """ complete openid signin """
    on_success = on_success or default_on_success
    on_failure = on_failure or default_on_failure
    
    consumer = Consumer(request.session, DjangoOpenIDStore())
    # make sure params are encoded in utf8
    params = dict((k,smart_unicode(v)) for k, v in request.GET.items())
    openid_response = consumer.complete(params, return_to)
            
    
    if openid_response.status == SUCCESS:
        return on_success(request, openid_response.identity_url,
                openid_response)
    elif openid_response.status == CANCEL:
        return on_failure(request, 'The request was canceled')
    elif openid_response.status == FAILURE:
        return on_failure(request, openid_response.message)
    elif openid_response.status == SETUP_NEEDED:
        return on_failure(request, 'Setup needed')
    else:
        assert False, "Bad openid status: %s" % openid_response.status

def default_on_success(request, identity_url, openid_response):
    """ default action on openid signin success """
    request.session['openid'] = from_openid_response(openid_response)
    return HttpResponseRedirect(clean_next(request.GET.get('next')))

def default_on_failure(request, message):
    """ default failure action on signin """
    return render('openid_failure.html', {
        'message': message
    })


def not_authenticated(func):
    """ decorator that redirect user to next page if
    he is already logged."""
    def decorated(request, *args, **kwargs):
        if request.user.is_authenticated():
            next = request.GET.get("next", "/")
            return HttpResponseRedirect(next)
        return func(request, *args, **kwargs)
    return decorated

@not_authenticated
def signin(request, template_name='authopenid/signin.html', redirect_field_name=REDIRECT_FIELD_NAME,
        openid_form=OpenidSigninForm, auth_form=AuthenticationForm):
    """
    signin page. It manage the legacy authentification (user/password) 
    and authentification with openid.

    :attr request: request object
    :attr template_name: string, name of template to use
    :attr redirect_field_name: string, field name used for redirect. by default 'next'
    :attr openid_form: form use for openid signin, by default `OpenidSigninForm`
    :attr auth_form: form object used for legacy authentification. 
    by default AuthentificationForm form auser auth contrib.
    
    """
    on_failure = signin_failure
    redirect_to = request.REQUEST.get(redirect_field_name, '')
    form1 = openid_form()
    form2 = auth_form()
    if request.POST:
        if not redirect_to or '//' in redirect_to or ' ' in redirect_to:
            redirect_to = settings.LOGIN_REDIRECT_URL     
        if 'bsignin' in request.POST.keys():
            form1 = openid_form(data=request.POST)
            if form1.is_valid():
                sreg_req = sreg.SRegRequest(optional=['nickname', 'email'])
                redirect_url = "%s%s?%s" % (
                        get_url_host(request),
                        reverse('user_complete_signin'), 
                        urllib.urlencode({ redirect_field_name: redirect_to })
                )
                return ask_openid(request, 
                        form1.cleaned_data['openid_url'], 
                        redirect_url, 
                        on_failure=signin_failure, 
                        sreg_request=sreg_req)
        elif 'blogin' in request.POST.keys():
            # perform normal django authentification
            form2 = auth_form(data=request.POST)
            if form2.is_valid():
                login(request, form2.get_user())
                if request.session.test_cookie_worked():
                    request.session.delete_test_cookie()
                return HttpResponseRedirect(redirect_to)
    return render(template_name, {
        'form1': form1,
        'form2': form2,
        redirect_field_name: redirect_to,
        'msg':  request.GET.get('msg',''),
        'sendpw_url': reverse('user_sendpw'),
    }, context_instance=RequestContext(request))

def complete_signin(request):
    """ in case of complete signin with openid """
    return complete(request, signin_success, signin_failure,
            get_url_host(request) + reverse('user_complete_signin'))


def signin_success(request, identity_url, openid_response):
    """
    openid signin success.

    If the openid is already registered, the user is redirected to 
    url set par next or in settings with OPENID_REDIRECT_NEXT variable.
    If none of these urls are set user is redirectd to /.

    if openid isn't registered user is redirected to register page.
    """

    openid_ = from_openid_response(openid_response)
    request.session['openid'] = openid_
    try:
        rel = UserAssociation.objects.get(openid_url__exact = str(openid_))
    except:
        # try to register this new user
        return register(request)
    user_ = rel.user
    if user_.is_active:
        user_.backend = "django.contrib.auth.backends.ModelBackend"
        login(request, user_)
        
    next = clean_next(request.GET.get('next'))
    return HttpResponseRedirect(next)

def is_association_exist(openid_url):
    """ test if an openid is already in database """
    is_exist = True
    try:
        uassoc = UserAssociation.objects.get(openid_url__exact = openid_url)
    except:
        is_exist = False
    return is_exist
    
def register_account(form):
    tmp_pwd = User.objects.make_random_password()
    user_ = User.objects.create_user(form.cleaned_data['username'],
             form.cleaned_data['email'], tmp_pwd)
    user_.backend = "django.contrib.auth.backends.ModelBackend"
    return user_

@not_authenticated
def register(request, template_name='authopenid/complete.html', 
            redirect_field_name=REDIRECT_FIELD_NAME, register_form=OpenidRegisterForm, 
            auth_form=AuthenticationForm, register_account=register_account):
    """
    register an openid.

    If user is already a member he can associate its openid with 
    its account.

    A new account could also be created and automaticaly associated
    to the openid.

    :attr request: request object
    :attr template_name: string, name of template to use, 'authopenid/complete.html' by default
    :attr redirect_field_name: string, field name used for redirect. by default 'next'
    :attr register_form: form use to create a new account. By default `OpenidRegisterForm`
    :attr auth_form: form object used for legacy authentification. 
    by default `OpenidVerifyForm` form auser auth contrib.
    :attr register_account: callback used to create a new account from openid. 
    It take the register_form as param.
    
    
    """

    is_redirect = False
    redirect_to = request.REQUEST.get(redirect_field_name, '')
    openid_ = request.session.get('openid', None)
    if openid_ is None or not openid_:
        return HttpResponseRedirect("%s?%s" % (reverse('user_signin') ,
                                urllib.urlencode({ redirect_field_name: redirect_to })))

    nickname = openid_.sreg.get('nickname', '')
    email = openid_.sreg.get('email', '')
    
    form1 = register_form(initial={
        'username': nickname,
        'email': email,
    }) 
    form2 = auth_form(initial={ 
        'username': nickname,
    })
    
    if request.POST:
        user_ = None
        if not redirect_to or '//' in redirect_to or ' ' in redirect_to:
            redirect_to = settings.LOGIN_REDIRECT_URL
        if 'bnewaccount' in request.POST.keys():
            form1 = register_form(data=request.POST)
            if form1.is_valid():
                user_ = register_account(form1)     
        elif 'bverify' in request.POST.keys():
            form2 = auth_form(data=request.POST)
            if form2.is_valid():
                user_ = form2.get_user()
        if user_ is not None:
            # associate the user to openid
            uassoc = UserAssociation(
                        openid_url=str(openid_),
                        user_id=user_.id
            )
            uassoc.save()
            login(request, user_)
            return HttpResponseRedirect(redirect_to) 
    
    return render(template_name, {
        'form1': form1,
        'form2': form2,
        'nickname': nickname,
        'email': email
    }, context_instance=RequestContext(request))



def signin_failure(request, message, template_name='authopenid/signin.html'):
    """
    falure with openid signin. Go back to signin page.

    template : "authopenid/signin.html"
    """
    next = clean_next(request.GET.get('next'))
    form_signin = OpenidSigninForm(initial={'next': next})
    form_auth = OpenidAuthForm(initial={'next': next})

    return render(template_name, {
        'msg': message,
        'form1': form_auth,
        'form2': form_signin,
    }, context_instance=RequestContext(request))

@not_authenticated
def signup(request, template_name='authopenid/signup.html'):
    """
    signup page. Create a legacy account

    url : /signup/"

    templates: authopenid/signup.html, authopenid/confirm_email.txt
    """
    action_signin = reverse('user_signin')
    next = clean_next(request.GET.get('next'))
    form = RegistrationForm(initial={'next':next})
    form_signin = OpenidSigninForm(initial={'next':next})
    
    if request.POST:
        form = RegistrationForm(request.POST)
        if form.is_valid():
            next = clean_next(form.cleaned_data.get('next'))
            user_ = User.objects.create_user( form.cleaned_data['username'],
                    form.cleaned_data['email'], form.cleaned_data['password1'])
           
            user_.backend = "django.contrib.auth.backends.ModelBackend"
            login(request, user_)
            
            # send email
            current_domain = Site.objects.get_current().domain
            subject = _("Welcome")
            message_template = loader.get_template(
                    'authopenid/confirm_email.txt'
            )
            message_context = Context({ 
                'site_url': 'http://%s/' % current_domain,
                'username': form.cleaned_data['username'],
                'password': form.cleaned_data['password1'] 
            })
            message = message_template.render(message_context)
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, 
                    [user_.email])
            
            return HttpResponseRedirect(next)
    
    return render(template_name, {
        'form': form,
        'form2': form_signin,
        }, context_instance=RequestContext(request))

@login_required
def signout(request):
    """
    signout from the website. Remove openid from session and kill it.

    url : /signout/"
    """
    try:
        del request.session['openid']
    except KeyError:
        pass
    next = clean_next(request.GET.get('next'))
    logout(request)
    
    return HttpResponseRedirect(next)
    
def xrdf(request, template_name='authopenid/yadis.xrdf'):
    url_host = get_url_host(request)
    return_to = [
        "%s%s" % (url_host, reverse('user_complete_signin'))
    ]
    return render(template_name, { 
        'return_to': return_to 
        }, context_instance=RequestContext(request))

@login_required
def account_settings(request, template_name='authopenid/settings.html'):
    """
    index pages to changes some basic account settings :
     - change password
     - change email
     - associate a new openid
     - delete account

    url : /

    template : authopenid/settings.html
    """
    msg = request.GET.get('msg', '')
    is_openid = True

    try:
        uassoc = UserAssociation.objects.get(
                user__username__exact=request.user.username
        )
    except:
        is_openid = False


    return render(template_name, {
        'msg': msg,
        'is_openid': is_openid
        }, context_instance=RequestContext(request))

@login_required
def changepw(request, template_name='authopenid/changepw.html'):
    """
    change password view.

    url : /changepw/
    template: authopenid/changepw.html
    """
    
    user_ = request.user
    
    if request.POST:
        form = ChangepwForm(request.POST, user=user_)
        if form.is_valid():
            user_.set_password(form.cleaned_data['password1'])
            user_.save()
            msg = _("Password changed.") 
            redirect = "%s?msg=%s" % (
                    reverse('user_account_settings'),
                    urlquote_plus(msg))
            return HttpResponseRedirect(redirect)
    else:
        form = ChangepwForm(user=user_)

    return render(template_name, {'form': form },
                                context_instance=RequestContext(request))

@login_required
def changeemail(request, template_name='authopenid/changeemail.html'):
    """ 
    changeemail view. It require password or openid to allow change.

    url: /changeemail/

    template : authopenid/changeemail.html
    """
    msg = request.GET.get('msg', '')
    extension_args = {}
    user_ = request.user
    
    redirect_to = get_url_host(request) + reverse('user_changeemail')

    if request.POST:
        form = ChangeemailForm(request.POST, user=user_)
        if form.is_valid():
            if not form.test_openid:
                user_.email = form.cleaned_data['email']
                user_.save()
                msg = _("Email changed.") 
                redirect = "%s?msg=%s" % (reverse('user_account_settings'),
                        urlquote_plus(msg))
                return HttpResponseRedirect(redirect)
            else:
                request.session['new_email'] = form.cleaned_data['email']
                return ask_openid(request, form.cleaned_data['password'], 
                        redirect_to, on_failure=emailopenid_failure)    
    elif not request.POST and 'openid.mode' in request.GET:
        return complete(request, emailopenid_success, 
                emailopenid_failure, redirect_to) 
    else:
        form = ChangeemailForm(initial={'email': user_.email},
                user=user_)
    
    return render(template_name, {
        'form': form,
        'msg': msg 
        }, context_instance=RequestContext(request))


def emailopenid_success(request, identity_url, openid_response):
    openid_ = from_openid_response(openid_response)

    user_ = request.user
    try:
        uassoc = UserAssociation.objects.get(
                openid_url__exact=identity_url
        )
    except:
        return emailopenid_failure(request, 
                _("No OpenID %s found associated in our database" % identity_url))

    if uassoc.user.username != request.user.username:
        return emailopenid_failure(request, 
                _("The OpenID %s isn't associated to current user logged in" % 
                    identity_url))
    
    new_email = request.session.get('new_email', '')
    if new_email:
        user_.email = new_email
        user_.save()
        del request.session['new_email']
    msg = _("Email Changed.")

    redirect = "%s?msg=%s" % (reverse('user_account_settings'),
            urlquote_plus(msg))
    return HttpResponseRedirect(redirect)
    

def emailopenid_failure(request, message):
    redirect_to = "%s?msg=%s" % (
            reverse('user_changeemail'), urlquote_plus(message))
    return HttpResponseRedirect(redirect_to)
 
@login_required
def changeopenid(request, template_name='authopenid/changeopenid.html'):
    """
    change openid view. Allow user to change openid 
    associated to its username.

    url : /changeopenid/

    template: authopenid/changeopenid.html
    """

    extension_args = {}
    openid_url = ''
    has_openid = True
    msg = request.GET.get('msg', '')
        
    user_ = request.user

    try:
        uopenid = UserAssociation.objects.get(user=user_)
        openid_url = uopenid.openid_url
    except:
        has_openid = False
    
    redirect_to = get_url_host(request) + reverse('user_changeopenid')
    if request.POST and has_openid:
        form = ChangeopenidForm(request.POST, user=user_)
        if form.is_valid():
            return ask_openid(request, form.cleaned_data['openid_url'],
                    redirect_to, on_failure=changeopenid_failure)
    elif not request.POST and has_openid:
        if 'openid.mode' in request.GET:
            return complete(request, changeopenid_success,
                    changeopenid_failure, redirect_to)    

    form = ChangeopenidForm(initial={'openid_url': openid_url }, user=user_)
    return render(template_name, {
        'form': form,
        'has_openid': has_openid, 
        'msg': msg 
        }, context_instance=RequestContext(request))

def changeopenid_success(request, identity_url, openid_response):
    openid_ = from_openid_response(openid_response)
    is_exist = True
    try:
        uassoc = UserAssociation.objects.get(openid_url__exact=identity_url)
    except:
        is_exist = False
        
    if not is_exist:
        try:
            uassoc = UserAssociation.objects.get(
                    user__username__exact=request.user.username
            )
            uassoc.openid_url = identity_url
            uassoc.save()
        except:
            uassoc = UserAssociation(user=request.user, 
                    openid_url=identity_url)
            uassoc.save()
    elif uassoc.user.username != request.user.username:
        return changeopenid_failure(request, 
                _('This OpenID is already associated with another account.'))

    request.session['openids'] = []
    request.session['openids'].append(openid_)

    msg = _("OpenID %s is now associated with your account." % identity_url) 
    redirect = "%s?msg=%s" % (
            reverse('user_account_settings'), 
            urlquote_plus(msg))
    return HttpResponseRedirect(redirect)
    

def changeopenid_failure(request, message):
    redirect_to = "%s?msg=%s" % (
            reverse('user_changeopenid'), 
            urlquote_plus(message))
    return HttpResponseRedirect(redirect_to)
  
@login_required
def delete(request, template_name='authopenid/delete.html'):
    """
    delete view. Allow user to delete its account. Password/openid are required to 
    confirm it. He should also check the confirm checkbox.

    url : /delete

    template : authopenid/delete.html
    """

    extension_args = {}
    
    user_ = request.user

    redirect_to = get_url_host(request) + reverse('user_delete') 
    if request.POST:
        form = DeleteForm(request.POST, user=user_)
        if form.is_valid():
            if not form.test_openid:
                user_.delete() 
                return signout(request)
            else:
                return ask_openid(request, form.cleaned_data['password'],
                        redirect_to, on_failure=deleteopenid_failure)
    elif not request.POST and 'openid.mode' in request.GET:
        return complete(request, deleteopenid_success, deleteopenid_failure,
                redirect_to) 
    
    form = DeleteForm(user=user_)

    msg = request.GET.get('msg','')
    return render(template_name, {
        'form': form, 
        'msg': msg, 
        }, context_instance=RequestContext(request))

def deleteopenid_success(request, identity_url, openid_response):
    openid_ = from_openid_response(openid_response)

    user_ = request.user
    try:
        uassoc = UserAssociation.objects.get(
                openid_url__exact=identity_url
        )
    except:
        return deleteopenid_failure(request,
                _("No OpenID %s found associated in our database" % identity_url))

    if uassoc.user.username == user_.username:
        user_.delete()
        return signout(request)
    else:
        return deleteopenid_failure(request,
                _("The OpenID %s isn't associated to current user logged in" % 
                    identity_url))
    
    msg = _("Account deleted.") 
    redirect = "/?msg=%s" % (urlquote_plus(msg))
    return HttpResponseRedirect(redirect)
    

def deleteopenid_failure(request, message):
    redirect_to = "%s?msg=%s" % (reverse('user_delete'), urlquote_plus(message))
    return HttpResponseRedirect(redirect_to)


def sendpw(request, template_name='authopenid/sendpw.html'):
    """
    send a new password to the user. It return a mail with 
    a new pasword and a confirm link in. To activate the 
    new password, the user should click on confirm link.

    url : /sendpw/

    templates :  authopenid/sendpw_email.txt, authopenid/sendpw.html
    """

    msg = request.GET.get('msg','')
    if request.POST:
        form = EmailPasswordForm(request.POST)
        if form.is_valid():
            new_pw = User.objects.make_random_password()
            confirm_key = UserPasswordQueue.objects.get_new_confirm_key()
            try:
                uqueue = UserPasswordQueue.objects.get(
                        user=form.user_cache
                )
            except:
                uqueue = UserPasswordQueue(
                        user=form.user_cache
                )
            uqueue.new_password = new_pw
            uqueue.confirm_key = confirm_key
            uqueue.save()
            # send email 
            current_domain = Site.objects.get_current().domain
            subject = _("Request for new password")
            message_template = loader.get_template(
                    'authopenid/sendpw_email.txt')
            message_context = Context({ 
                'site_url': 'http://%s' % current_domain,
                'confirm_key': confirm_key,
                'username': form.user_cache.username,
                'password': new_pw,
                'url_confirm': reverse('user_confirmchangepw'),
            })
            message = message_template.render(message_context)
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, 
                    [form.user_cache.email])
            msg = _("A new password has been sent to your email address.")
    else:
        form = EmailPasswordForm()
        
    return render(template_name, {
        'form': form,
        'msg': msg 
        }, context_instance=RequestContext(request))


def confirmchangepw(request):
    """
    view to set new password when the user click on confirm link
    in its mail. Basically it check if the confirm key exist, then
    replace old password with new password and remove confirm
    ley from the queue. Then it redirect the user to signin
    page.

    url : /sendpw/confirm/?key

    """
    confirm_key = request.GET.get('key', '')
    if not confirm_key:
        return HttpResponseRedirect('/')

    try:
        uqueue = UserPasswordQueue.objects.get(
                confirm_key__exact=confirm_key
        )
    except:
        msg = _("Could not change password. Confirmation key '%s'\
                is not registered." % confirm_key) 
        redirect = "%s?msg=%s" % (
                reverse('user_sendpw'), urlquote_plus(msg))
        return HttpResponseRedirect(redirect)

    try:
        user_ = User.objects.get(id=uqueue.user.id)
    except:
        msg = _("Can not change password. User don't exist anymore \
                in our database.") 
        redirect = "%s?msg=%s" % (reverse('user_sendpw'), 
                urlquote_plus(msg))
        return HttpResponseRedirect(redirect)

    user_.set_password(uqueue.new_password)
    user_.save()
    uqueue.delete()
    msg = _("Password changed for %s. You may now sign in." % 
            user_.username) 
    redirect = "%s?msg=%s" % (reverse('user_signin'), 
                                        urlquote_plus(msg))

    return HttpResponseRedirect(redirect)