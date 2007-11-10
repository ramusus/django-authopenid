"""
 Copyright 2007 Benoît Chesneau 
 Licensed under the Apache License, Version 2.0 (the "License"); 
 you may not use this file except in compliance with the License. 
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0 
 
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""


from django.http import HttpResponse, HttpResponseRedirect, get_host
from django.shortcuts import get_object_or_404, render_to_response as render
from django.template import RequestContext, loader, Context
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth import authenticate,login,logout
from django.core.urlresolvers import reverse
from django.utils.html import escape
from django.utils.translation import ugettext as _
from django.contrib.sites.models import Site
from django.utils.encoding import smart_str
from django.utils.http import urlquote_plus, urlquote

from openid.consumer.consumer import Consumer
from openid.consumer.discover import DiscoveryFailure
from yadis import xri

import urllib

from django_openidconsumer.util import OpenID, DjangoOpenIDStore, from_openid_response
from django_openidconsumer.views import complete, is_valid_next_url, get_url_host
from django_openidconsumer.forms import OpenidSigninForm

from models import UserAssociation, UserPasswordQueue
from forms import OpenidAuthForm, OpenidRegisterForm, OpenidVerifyForm, RegistrationForm, ChangepwForm, ChangeemailForm, ChangeopenidForm, DeleteForm, EmailPasswordForm
from decorators import username_test

def ask_openid(request, openid_url, redirect_to, on_failure=None, extension_args=None):
    """ basic function to ask openid and return response """

    on_failure = on_failure or signin_failure
    extension_args = extension_args or {}

    trust_root = getattr(
        settings, 'OPENID_TRUST_ROOT', get_url_host(request) + '/'
    )
    if xri.identifierScheme(openid_url) == 'XRI' and getattr(
            settings, 'OPENID_DISALLOW_INAMES', False
    ):
        msg = _("i-names are not supported")
        return on_failure(request,msg)
    consumer = Consumer(request.session, DjangoOpenIDStore())
    try:
        auth_request = consumer.begin(openid_url)
    except DiscoveryFailure:
        msg =_("The OpenID %s was invalid" % openid_url)
        return on_failure(request,msg)

    # Add extension args (for things like simple registration)
    for name, value in extension_args.items():
        namespace, key = name.split('.', 1)
        auth_request.addExtensionArg(namespace, key, value)
    redirect_url = auth_request.redirectURL(trust_root, redirect_to)
    return HttpResponseRedirect(redirect_url)



def signin(request):
    """
    signin page. It manage the legacy authentification (user/password) 
    and authentification with openid.

    url: /signin/
    
    template : authopenid/signin.htm
    """

    on_failure = signin_failure
    extension_args = {}
    next = ''


    if request.GET.get('next') and is_valid_next_url(request.GET['next']):
        next = request.GET.get('next', '').strip()
    if not next or not is_valid_next_url(next):
        next = getattr(settings, 'OPENID_REDIRECT_NEXT', '/')

    if request.user.is_authenticated():
        return HttpResponseRedirect(next)


    form_signin = OpenidSigninForm(initial={'next':next})
    form_auth = OpenidAuthForm(initial={'next':next})

    if request.POST:   
        if 'bsignin' in request.POST.keys():
            form_signin = OpenidSigninForm(request.POST)
            if form_signin.is_valid():
                next = form_signin.cleaned_data['next']
                if not next:
                    next = getattr(settings, 'OPENID_REDIRECT_NEXT', '/')

                extension_args['sreg.optional'] = 'email,nickname'
                redirect_to = "%s?next=%s" % (
                        get_url_host(request) + reverse('django_authopenid.views.complete_signin'), 
                        urllib.urlencode({'next':next}))

                return ask_openid(request, 
                        form_signin.cleaned_data['openid_url'], 
                        redirect_to, 
                        on_failure=signin_failure, 
                        extension_args=extension_args)

        elif 'blogin' in request.POST.keys():
            # perform normal django authentification
            form_auth = OpenidAuthForm(request.POST)
            if form_auth.is_valid():
                user = form_auth.get_user()
                login(request, user)

                next = form_auth.cleaned_data['next']
                if not next:
                    next = getattr(settings, 'OPENID_REDIRECT_NEXT', '/')
                return HttpResponseRedirect(next)


    return render('authopenid/signin.html', {
        'form1': form_auth,
        'form2': form_signin,
        'action': request.path,
        'msg':  request.GET.get('msg',''),
        'sendpw_url': reverse('django_authopenid.views.sendpw'),
    })

def complete_signin(request):
    """ in case of complete signin with openid """
    return complete(request, signin_success, signin_failure)


def signin_success(request, identity_url, openid_response):
    """
    openid signin success.

    If the openid is already registered, the user is redirected to 
    url set par next or in settings with OPENID_REDIRECT_NEXT variable.
    If none of these urls are set user is redirectd to /.

    if openid isn't registered user is redirected to register page.
    """

    request.session['openids'] = []
    openid=from_openid_response(openid_response)
    request.session['openids'].append(openid)

    try:
        rel = UserAssociation.objects.get(openid_url__exact=str(openid))
    except:
        # try to register this new user
        return register(request)
    user = rel.user
    if user.is_active:
        user.backend = "django.contrib.auth.backends.ModelBackend"
        login(request,user)

    next = request.GET.get('next', '').strip()
    if not next or not is_valid_next_url(next):
        next = getattr(settings, 'OPENID_REDIRECT_NEXT', '/')
    
    return HttpResponseRedirect(next)

def is_association_exist(openid_url):
    """ test if an openid is already in database """
    is_exist=True
    try:
        o=UserAssociation.objects.get(openid_url__exact=openid_url)
    except:
        is_exist=False
    return is_exist

def register(request):
    """
    register an openid.

    If user is already a member he can associate its openid with 
    its account.

    A new account could also be created and automaticaly associated
    to the openid.

    url : /complete/

    template : authopenid/complete.html
    """

    is_redirect = False
    next = request.GET.get('next', '').strip()
    if not next or not is_valid_next_url(next):
        next = getattr(settings, 'OPENID_REDIRECT_NEXT', '/')


    openids = request.session.get('openids', [])
    if openids and len(openids)>0:
        openid = openids[-1] # Last authenticated OpenID
    else:
         return HttpResponseRedirect(reverse('django_authopenid.views.signin') + next)

    nickname = openid.sreg.get('nickname', '')
    email = openid.sreg.get('email', '')
    
    form1 = OpenidRegisterForm(initial={
        'next': next,
        'username': nickname,
        'email': email,
    }) 
    form2 = OpenidVerifyForm(initial={
        'next': next,
        'username': nickname,
    })
    
    if request.POST:
        just_completed=False
        if 'bnewaccount' in request.POST.keys():
            form1 = OpenidRegisterForm(request.POST)
            if form1.is_valid():
                next = form1.cleaned_data['next']
                if not next:
                    next = getattr(settings, 'OPENID_REDIRECT_NEXT', '/')
                is_redirect = True
                tmp_pwd = User.objects.make_random_password()
                user = User.objects.create_user(form1.cleaned_data['username'],form1.cleaned_data['email'], tmp_pwd)
                
                # make association with openid
                ua = UserAssociation(openid_url=str(openid),user_id=user.id)
                ua.save()
                    
                # login 
                user.backend = "django.contrib.auth.backends.ModelBackend"
                login(request, user)
        elif 'bverify' in request.POST.keys():
            form2 = OpenidVerifyForm(request.POST)
            if form2.is_valid():
                is_redirect = True
                next = form2.cleaned_data['next']
                if not next:
                    next = getattr(settings, 'OPENID_REDIRECT_NEXT', '/')
                user = form2.get_user()

                ua = UserAssociation(openid_url=str(openid),user_id=user.id)
                ua.save()
                login(request, user)
        
        # redirect, can redirect only if forms are valid.
        if is_redirect:
            return HttpResponseRedirect(next)
    
    
    
    return render('authopenid/complete.html', {
        'form1': form1,
        'form2': form2,
        'action': reverse('django_authopenid.views.register'),
        'nickname': nickname,
        'email': email
    }, context_instance=RequestContext(request))

def signin_failure(request, message):
    """
    falure with openid signin. Go back to signin page.

    template : "authopenid/openid.html"
    """
    request_path=reverse('friendsnippets.django_authopenid.views.signin')
    if request.GET.get('next'):
        request_path += '?' + urllib.urlencode({
            'next': request.GET['next']
        })

    form_signin = OpenidSigninForm(initial={'next':next})
    form_auth = OpenidAuthForm(initial={'next':next})

    return render('authopenid/signin.html', {
        'msg': message,
        'form1': form_auth,
        'form2': form_signin,
    })


def signup(request):
    """
    signup page. Create a legacy account

    url : /signup/"

    templates: authopenid/signup.html, authopenid/confirm_email.txt
    """
    action_signin = reverse('django_authopenid.views.signin')

    next = request.GET.get('next', '/')
    form = RegistrationForm(initial={'next':next})
    form_signin = OpenidSigninForm(initial={'next':next})

    if request.user.is_authenticated():
        return HttpResponseRedirect(next)
    
    if request.POST:
        form = RegistrationForm(request.POST)
        if form.is_valid():

            next = form.cleaned_data['next']
            if not next: next = '/'

            user = User.objects.create_user(form.cleaned_data['username'],form.cleaned_data['email'], form.cleaned_data['password1'])
           
            user.backend = "django.contrib.auth.backends.ModelBackend"
            login(request, user)
            
            # send email
            current_domain = Site.objects.get_current().domain
            subject = _("Welcome")
            message_template = loader.get_template('authopenid/confirm_email.txt')
            message_context = Context({ 'site_url': 'http://%s/' % current_domain,
                                        'username': form.cleaned_data['username'],
                                        'password': form.cleaned_data['password1'] })
            message = message_template.render(message_context)
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
            
            return HttpResponseRedirect(next)
    
    return render('authopenid/signup.html', {
        'form': form,
        'form2': form_signin,
        'action': request.path,
        'action_signin': action_signin,
        },context_instance=RequestContext(request))

    
def signout(request):
    """
    signout from the website. Remove openid from session and kill it.

    url : /signout/"
    """
    request.session['openids'] = []
    next = request.GET.get('next', '/')
    if not is_valid_next_url(next):
        next = '/'

    logout(request)
    
    return HttpResponseRedirect(next)



def account_settings(request,username=None):
    """
    index pages to changes some basic account settings :
     - change password
     - change email
     - associate a new openid
     - delete account

    url : /username/

    template : account/settings.html
    """
    msg = request.GET.get('msg', '')
    is_openid = True

    try:
        o=UserAssociation.objects.get(user__username__exact=username)
    except:
        is_openid = False


    return render('account/settings.html',
            {'msg': msg, 'settings_path': request.path, 'is_openid': is_openid},
            context_instance=RequestContext(request))
account_settings = username_test(account_settings, 'django_authopenid.views.account_settings')


def changepw(request,username):
    """
    change password view.

    url : /username/changepw/
    template: account/changepw.html
    """
    
    u = get_object_or_404(User, username=username)
    
    if request.POST:
        form = ChangepwForm(request.POST)
        if form.is_valid():
            u.set_password(form.cleaned_data['password1'])
            u.save()
            msg=_("Password changed.") 
            redirect="%s?msg=%s" % (reverse('django_authopenid.views.account_settings',kwargs={'username': request.user.username}),urlquote_plus(msg))
            return HttpResponseRedirect(redirect)
    else:
        form=ChangepwForm(initial={'username':request.user.username})

    return render('account/changepw.html', {'form': form },
                                context_instance=RequestContext(request))

changepw = username_test(changepw, 'django_authopenid.views.changepw')


def changeemail(request,username):
    """ 
    changeemail view. It require password or openid to allow change.

    url: /username/changeemail/

    template : account/changeemail.html
    """

    extension_args = {}
 
    u = get_object_or_404(User, username=username) 
    
    if request.POST:
        form = ChangeemailForm(request.POST)
        if form.is_valid():
            if not form.test_openid:
                u.email = form.cleaned_data['email']
                u.save()
                msg=_("Email changed.") 
                redirect="%s?msg=%s" % (reverse('django_authopenid.views.account_settings', kwargs={'username': request.user.username}),urlquote_plus(msg))
                return HttpResponseRedirect(redirect)
            else:
                redirect_to = "%s?new_email=%s" % (get_url_host(request) + reverse('django_authopenid.views.changeemail',kwargs={'username':username}),form.cleaned_data['email'])
                
                return ask_openid(request, form.cleaned_data['password'], redirect_to, on_failure=emailopenid_failure)    
    elif not request.POST and 'openid.mode' in request.GET:
        return complete(request, emailopenid_success, emailopenid_failure) 
    else:
        form = ChangeemailForm(initial={
                                        'email': u.email,
                                        'username':request.user.username
                                        })
    
    return render('account/changeemail.html', 
            {'form': form }, context_instance=RequestContext(request))
changeemail = username_test(changeemail, 'django_authopenid.views.changeemail')

def emailopenid_success(request, identity_url, openid_response):
    openid=from_openid_response(openid_response)

    try:
        u=User.objects.get(username=request.user.username)
    except:
        raise Http404

    try:
        o=UserAssociation.objects.get(openid_url__exact=identity_url)
    except:
        return emailopenid_failure(request, _("No openid % associated in our database" % identity_url))

    if o.user.username != request.user.username:
        return emailopenid_failure(request, _("The openid %s isn't associated to current logged user" % identity_url))
    
    new_email=request.GET.get('new_email', '')
    if new_email:
        u.email=new_email
        u.save()
    msg=_("Email Changed.")

    redirect="%s?msg=%s" % (reverse('django_authopenid.views.account_settings',kwargs={'username': request.user.username}),urlquote_plus(msg))
    return HttpResponseRedirect(redirect)
    

def emailopenid_failure(request, message):
    redirect_to="%s?msg=%s" % (reverse('django_authopenid.views.changeemail',kwargs={'username':request.user.username}), urlquote_plus(message))

    return HttpResponseRedirect(redirect_to)
 


def changeopenid(request, username):
    """
    change openid view. Allow user to change openid associated to its username.

    url : /username/changeopenid/

    template: account/changeopenid.html
    """

    extension_args = {}
    openid_url=''
    has_openid=True
    msg = request.GET.get('msg', '')
        
    u = get_object_or_404(User, username=username)

    try:
        uopenid=UserAssociation.objects.get(user=u)
        openid_url = uopenid.openid_url
    except:
        has_openid=False
         
    if request.POST and has_openid:
        form=ChangeopenidForm(request.POST)
        if form.is_valid():
            redirect_to = get_url_host(request) + reverse('django_authopenid.views.changeopenid',kwargs={'username':username})
            return ask_openid(request, form.cleaned_data['openid_url'], redirect_to, on_failure=changeopenid_failure)
    elif not request.POST and has_openid:
        if 'openid.mode' in request.GET:
            return complete(request, changeopenid_success, changeopenid_failure)    

    form = ChangeopenidForm(initial={'openid_url': openid_url, 'username':request.user.username })
    return render('account/changeopenid.html', {'form': form,
        'has_openid': has_openid, 'msg': msg }, context_instance=RequestContext(request))

changeopenid = username_test(changeopenid, 'django_authopenid.views.changeopenid')

def changeopenid_success(request, identity_url, openid_response):
    openid=from_openid_response(openid_response)
    is_exist=True
    try:
        o=UserAssociation.objects.get(openid_url__exact=identity_url)
    except:
        is_exist=False
        
    if not is_exist:
        try:
            o=UserAssociation.objects.get(user__username__exact=request.user.username)
            o.openid_url=identity_url
            o.save()
        except:
            o=UserAssociation(user=request.user,openid_url=identity_url)
            o.save()
    elif o.user.username != request.user.username:
        return changeopenid_failure(request, _('This openid is already associated with another account.'))

    request.session['openids'] = []
    request.session['openids'].append(openid)

    msg=_("Openid %s associated with your account." % identity_url) 
    redirect="%s?msg=%s" % (reverse('django_authopenid.views.account_settings', kwargs={'username':request.user.username}), urlquote_plus(msg))
    return HttpResponseRedirect(redirect)
    

def changeopenid_failure(request, message):
    redirect_to="%s?msg=%s" % (reverse('django_authopenid.views.changeopenid',kwargs={'username':request.user.username}), urlquote_plus(message))
    return HttpResponseRedirect(redirect_to)
    
def delete(request,username):
    """
    delete view. Allow user to delete its account. Password/openid are required to 
    confirm it. He should also check the confirm checkbox.

    url : /username/delete

    template : account/delete.html
    """

    extension_args={}
    
    u = get_object_or_404(User, username=username)

    if request.POST:
        form = DeleteForm(request.POST)
        if form.is_valid():
            if not form.test_openid:
                u.delete()
                from friendsnippets.django_openidconsumer.views import signout
                return signout(request)
            else:
                redirect_to = get_url_host(request) + reverse('django_authopenid.views.delete',kwargs={'username':username})
                return ask_openid(request, form.cleaned_data['password'], redirect_to, on_failure=deleteopenid_failure)
    elif not request.POST and 'openid.mode' in request.GET:
        return complete(request, deleteopenid_success, deleteopenid_failure) 
    
    form = DeleteForm(initial={'username': username})

    msg = request.GET.get('msg','')
    return render('account/delete.html', {'form': form, 'msg': msg, },
                                        context_instance=RequestContext(request))

delete = username_test(delete, 'django_authopenid.views.delete')

def deleteopenid_success(request, identity_url, openid_response):
    openid=from_openid_response(openid_response)

    try:
        u=User.objects.get(username=request.user.username)
    except:
        raise Http404

    try:
        o=UserAssociation.objects.get(openid_url__exact=identity_url)
    except:
        return deleteopenid_failure(request, _("No openid % associated in our database" % identity_url))

    if o.user.username == request.user.username:
        u.delete()
        return signout(request)
    else:
        return deleteopenid_failure(request, _("The openid %s isn't associated to current logged user" % identity_url))
    
    msg=_("Account deleted.") 
    redirect="/?msg=%s" % (urlquote_plus(msg))
    return HttpResponseRedirect(redirect)
    

def deleteopenid_failure(request, message):
    redirect_to="%s?msg=%s" % (reverse('django_authopenid.views.delete',kwargs={'username':request.user.username}), urlquote_plus(message))

    return HttpResponseRedirect(redirect_to)


def sendpw(request):
    """
    send a new password to the user. It return a mail with 
    a new pasword and a confirm link in. To activate the 
    new password, the user should click on confirm link.

    url : /sendpw/

    templates :  account/sendpw_email.txt, account/sendpw.html
    """

    msg = request.GET.get('msg','')
    if request.POST:
        form = EmailPasswordForm(request.POST)
        if form.is_valid():
            new_pw = User.objects.make_random_password()
            confirm_key = UserPasswordQueue.objects.get_new_confirm_key()
            try:
                q=UserPasswordQueue.objects.get(user=form.user_cache)
            except:
                q=UserPasswordQueue(user=form.user_cache)
            q.new_password=new_pw
            q.confirm_key = confirm_key
            q.save()
            # send email
            from django.core.mail import send_mail
            current_domain = Site.objects.get_current().domain
            subject = _("Request for a new password")
            message_template = loader.get_template('account/sendpw_email.txt')
            message_context = Context({ 'site_url': 'http://%s' % current_domain,
                'confirm_key': confirm_key,
                'username': form.user_cache.username,
                'password': new_pw,
                'url_confirm': reverse('django_authopenid.views.confirmchangepw'),
            })
            message = message_template.render(message_context)
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [form.user_cache.email])
            msg=_("A new password has been sent to your email")
    else:
        form = EmailPasswordForm()
        
    return render('account/sendpw.html', {'form': form,
            'msg': msg, },
            context_instance=RequestContext(request))


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
        q = UserPasswordQueue.objects.get(confirm_key__exact=confirm_key)
    except:
        msg=_("Can not change password. Confirmation key '%s' isn't registered." % confirm_key) 
        redirect="%s?msg=%s" % (reverse('django_authopenid.views.sendpw'),urlquote_plus(msg))
        return HttpResponseRedirect(redirect)

    try:
        user = User.objects.get(id=q.user.id)
    except:
        msg=_("Can not change password. User don't exist anymore in our database.") 
        redirect="%s?msg=%s" % (reverse('django_authopenid.views.sendpw'),urlquote_plus(msg))
        return HttpResponseRedirect(redirect)

    user.set_password(q.new_password)
    user.save()
    q.delete()
    msg=_("Password changed for %s. You could now sign-in" % user.username) 
    redirect="%s?msg=%s" % (reverse('django_authopenid.views.signin'), 
                                        urlquote_plus(msg))

    return HttpResponseRedirect(redirect)

       

    
    


    






