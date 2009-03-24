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
from django.contrib.auth.forms import *
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
from django_authopenid.models import UserAssociation
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
        openid_form=OpenidSigninForm, auth_form=AuthenticationForm, on_failure=None):
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
    if on_failure is None:
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
                        on_failure=on_failure, 
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
        'msg':  request.GET.get('msg','')
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
    user_ = User.objects.create_user(form.cleaned_data['username'], form.cleaned_data['email'])
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
        redirect_field_name: redirect_to,
        'nickname': nickname,
        'email': email
    }, context_instance=RequestContext(request))


def signin_failure(request, message, template_name='authopenid/signin.html',
        redirect_field_name=REDIRECT_FIELD_NAME, openid_form=OpenidSigninForm, 
        auth_form=AuthenticationForm):
    """
    falure with openid signin. Go back to signin page.
    
    :attr request: request object
    :attr template_name: string, name of template to use, default is 'authopenid/signin.html'
    :attr redirect_field_name: string, field name used for redirect. by default 'next'
    :attr openid_form: form use for openid signin, by default `OpenidSigninForm`
    :attr auth_form: form object used for legacy authentification. 
    by default AuthentificationForm form auser auth contrib.

    """
    return render(template_name, {
        'msg': message,
        'form1': openid_form(),
        'form2': auth_form(),
        redirect_field_name: request.REQUEST.get(redirect_field_name, '')
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
def password_change(request, template_name='authopenid/password_change_form.html', 
        set_password_form=SetPasswordForm, change_password_form=PasswordChangeForm,
        post_change_redirect=None):
    """
    View that allow the user to set a password. Only 
    """
    if post_change_redirect is None:
        post_change_redirect = settings.LOGIN_REDIRECT_URL

    set_password = False
    if request.user.has_usable_password():
        change_form = change_password_form
    else:
        set_password = True
        change_form = set_password_form

    if request.POST:
        form = change_form(request.user, request.POST)
        print form.__class__.__name__
        print form.is_valid()
        if form.is_valid():
            form.save()
            msg = urllib.quote(_("Password changed"))
            redirect_to = "%s?%s" % (post_change_redirect, 
                                urllib.urlencode({ "msg": msg }))
            print redirect_to
            return HttpResponseRedirect(redirect_to)
    else:
        
        form = change_form(request.user)
        print form.__class__.__name__

    return render(template_name, {
        'form': form,
        'set_password': set_password
    }, context_instance=RequestContext(request))