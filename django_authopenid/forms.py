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

from django import forms
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.utils.translation import ugettext as _
from django.conf import settings

import re


# needed for some linux distributions like debian
try:
    from openid.yadis import xri
except ImportError:
    from yadis import xri
    
from django_authopenid.utils import clean_next

class OpenidSigninForm(forms.Form):
    """ signin form """
    openid_url = forms.CharField(max_length=255, 
            widget=forms.widgets.TextInput(attrs={'class': 'required openid'}))
            
    def clean_openid_url(self):
        """ test if openid is accepted """
        if 'openid_url' in self.cleaned_data:
            openid_url = self.cleaned_data['openid_url']
            if xri.identifierScheme(openid_url) == 'XRI' and getattr(
                settings, 'OPENID_DISALLOW_INAMES', False
                ):
                raise forms.ValidationError(_('i-names are not supported'))
            return self.cleaned_data['openid_url']

attrs_dict = { 'class': 'required login' }
username_re = re.compile(r'^\w+$')

class OpenidRegisterForm(forms.Form):
    """ openid signin form """
    next = forms.CharField(max_length=255, widget=forms.HiddenInput(), 
            required=False)
    username = forms.CharField(max_length=30, 
            widget=forms.widgets.TextInput(attrs=attrs_dict))
    email = forms.EmailField(widget=forms.TextInput(attrs=dict(attrs_dict, 
        maxlength=200)), label=u'Email address')
    
    def clean_username(self):
        """ test if username is valid and exist in database """
        if 'username' in self.cleaned_data:
            if not username_re.search(self.cleaned_data['username']):
                raise forms.ValidationError(_("Usernames can only contain \
                    letters, numbers and underscores"))
            try:
                user = User.objects.get(
                        username__exact = self.cleaned_data['username']
                        )
            except User.DoesNotExist:
                return self.cleaned_data['username']
            except User.MultipleObjectsReturned:
                raise forms.ValidationError(u'There is already more than one \
                    account registered with that username. Please try \
                    another.')
            raise forms.ValidationError(_("This username is already \
                taken. Please choose another."))
            
    def clean_email(self):
        """For security reason one unique email in database"""
        if 'email' in self.cleaned_data:
            try:
                user = User.objects.get(email = self.cleaned_data['email'])
            except User.DoesNotExist:
                return self.cleaned_data['email']
            except User.MultipleObjectsReturned:
                raise forms.ValidationError(u'There is already more than one \
                    account registered with that e-mail address. Please try \
                    another.')
            raise forms.ValidationError(_("This email is already \
                registered in our database. Please choose another."))
 
    
class OpenidVerifyForm(forms.Form):
    """ openid verify form (associate an openid with an account) """
    next = forms.CharField(max_length=255, widget = forms.HiddenInput(), 
            required=False)
    username = forms.CharField(max_length=30, 
            widget=forms.widgets.TextInput(attrs=attrs_dict))
    password = forms.CharField(max_length=128, 
            widget=forms.widgets.PasswordInput(attrs=attrs_dict))
    
    def __init__(self, data=None, files=None, auto_id='id_%s',
            prefix=None, initial=None): 
        super(OpenidVerifyForm, self).__init__(data, files, auto_id,
                prefix, initial)
        self.user_cache = None

    def clean_username(self):
        """ validate username """
        if 'username' in self.cleaned_data:
            if not username_re.search(self.cleaned_data['username']):
                raise forms.ValidationError(_("Usernames can only contain \
                    letters, numbers and underscores"))
            try:
                user = User.objects.get(
                        username__exact = self.cleaned_data['username']
                )
            except User.DoesNotExist:
                raise forms.ValidationError(_("This username don't exist. \
                        Please choose another."))
            except User.MultipleObjectsReturned:
                raise forms.ValidationError(u'Somehow, that username is in \
                    use for multiple accounts. Please contact us to get this \
                    problem resolved.')
            return self.cleaned_data['username']
            
    def clean_password(self):
        """ test if password is valid for this user """
        if 'username' in self.cleaned_data and \
                'password' in self.cleaned_data:
            self.user_cache =  authenticate(
                    username = self.cleaned_data['username'], 
                    password = self.cleaned_data['password']
            )
            if self.user_cache is None:
                raise forms.ValidationError(_("Please enter a valid \
                    username and password. Note that both fields are \
                    case-sensitive."))
            elif self.user_cache.is_active == False:
                raise forms.ValidationError(_("This account is inactive."))
            return self.cleaned_data['password']
            
    def get_user(self):
        """ get authenticated user """
        return self.user_cache


attrs_dict = { 'class': 'required' }
username_re = re.compile(r'^\w+$')

class RegistrationForm(forms.Form):
    """ legacy registration form """

    next = forms.CharField(max_length=255, widget=forms.HiddenInput(), 
            required=False)
    username = forms.CharField(max_length=30,
            widget=forms.TextInput(attrs=attrs_dict),
            label=u'Username')
    email = forms.EmailField(widget=forms.TextInput(attrs=dict(attrs_dict,
            maxlength=200)), label=u'Email address')
    password1 = forms.CharField(widget=forms.PasswordInput(attrs=attrs_dict),
            label=u'Password')
    password2 = forms.CharField(widget=forms.PasswordInput(attrs=attrs_dict),
            label=u'Password (again, to catch typos)')

    def clean_username(self):
        """
        Validates that the username is alphanumeric and is not already
        in use.
        
        """
        if 'username' in self.cleaned_data:
            if not username_re.search(self.cleaned_data['username']):
                raise forms.ValidationError(u'Usernames can only contain \
                        letters, numbers and underscores')
            try:
                user = User.objects.get(
                        username__exact = self.cleaned_data['username']
                )

            except User.DoesNotExist:
                return self.cleaned_data['username']
            except User.MultipleObjectsReturned:
                raise forms.ValidationError(u'Somehow, that username is in \
                    use for multiple accounts. Please contact us to get this \
                    problem resolved.')
            raise forms.ValidationError(u'This username is already taken. \
                    Please choose another.')

    def clean_email(self):
        """ validate if email exist in database
        :return: raise error if it exist """
        if 'email' in self.cleaned_data:
            try:
                user = User.objects.get(email = self.cleaned_data['email'])
            except User.DoesNotExist:
                return self.cleaned_data['email']
            except User.MultipleObjectsReturned:
                raise forms.ValidationError(u'There is already more than one \
                    account registered with that e-mail address. Please try \
                    another.')
            raise forms.ValidationError(u'This email is already registered \
                    in our database. Please choose another.')
        return self.cleaned_data['email']
    
    def clean_password2(self):
        """
        Validates that the two password inputs match.
        
        """
        if 'password1' in self.cleaned_data and \
                'password2' in self.cleaned_data and \
                self.cleaned_data['password1'] == \
                self.cleaned_data['password2']:
            return self.cleaned_data['password2']
        raise forms.ValidationError(u'You must type the same password each \
                time')


class ChangepwForm(forms.Form):
    """ change password form """
    oldpw = forms.CharField(widget=forms.PasswordInput(attrs=attrs_dict))
    password1 = forms.CharField(widget=forms.PasswordInput(attrs=attrs_dict))
    password2 = forms.CharField(widget=forms.PasswordInput(attrs=attrs_dict))

    def __init__(self, data=None, user=None, *args, **kwargs):
        if user is None:
            raise TypeError("Keyword argument 'user' must be supplied")
        super(ChangepwForm, self).__init__(data, *args, **kwargs)
        self.user = user

    def clean_oldpw(self):
        """ test old password """
        if not self.user.check_password(self.cleaned_data['oldpw']):
            raise forms.ValidationError(_("Old password is incorrect. \
                    Please enter the correct password."))
        return self.cleaned_data['oldpw']
    
    def clean_password2(self):
        """
        Validates that the two password inputs match.
        """
        if 'password1' in self.cleaned_data and \
                'password2' in self.cleaned_data and \
           self.cleaned_data['password1'] == self.cleaned_data['password2']:
            return self.cleaned_data['password2']
        raise forms.ValidationError(_("new passwords do not match"))
        
        
class ChangeemailForm(forms.Form):
    """ change email form """
    email = forms.EmailField(widget=forms.TextInput(attrs=dict(attrs_dict, 
        maxlength=200)), label=u'Email address')
    password = forms.CharField(widget=forms.PasswordInput(attrs=attrs_dict))

    def __init__(self, data=None, files=None, auto_id='id_%s', prefix=None, \
            initial=None, user=None):
        if user is None:
            raise TypeError("Keyword argument 'user' must be supplied")
        super(ChangeemailForm, self).__init__(data, files, auto_id, 
                prefix, initial)
        self.test_openid = False
        self.user = user
        
        
    def clean_email(self):
        """ check if email don't exist """
        if 'email' in self.cleaned_data:
            if self.user.email != self.cleaned_data['email']:
                try:
                    user = User.objects.get(email = self.cleaned_data['email'])
                except User.DoesNotExist:
                    return self.cleaned_data['email']
                except User.MultipleObjectsReturned:
                    raise forms.ValidationError(u'There is already more than one \
                        account registered with that e-mail address. Please try \
                        another.')
                raise forms.ValidationError(u'This email is already registered \
                    in our database. Please choose another.')
        return self.cleaned_data['email']
        

    def clean_password(self):
        """ check if we have to test a legacy account or not """
        if 'password' in self.cleaned_data:
            if not self.user.check_password(self.cleaned_data['password']):
                self.test_openid = True
        return self.cleaned_data['password']
                
class ChangeopenidForm(forms.Form):
    """ change openid form """
    openid_url = forms.CharField(max_length=255,
            widget=forms.TextInput(attrs={'class': "required" }))

    def __init__(self, data=None, user=None, *args, **kwargs):
        if user is None:
            raise TypeError("Keyword argument 'user' must be supplied")
        super(ChangeopenidForm, self).__init__(data, *args, **kwargs)
        self.user = user

class DeleteForm(forms.Form):
    """ confirm form to delete an account """
    confirm = forms.CharField(widget=forms.CheckboxInput(attrs=attrs_dict))
    password = forms.CharField(widget=forms.PasswordInput(attrs=attrs_dict))

    def __init__(self, data=None, files=None, auto_id='id_%s',
            prefix=None, initial=None, user=None):
        super(DeleteForm, self).__init__(data, files, auto_id, prefix, initial)
        self.test_openid = False
        self.user = user

    def clean_password(self):
        """ check if we have to test a legacy account or not """
        if 'password' in self.cleaned_data:
            if not self.user.check_password(self.cleaned_data['password']):
                self.test_openid = True
        return self.cleaned_data['password']


class EmailPasswordForm(forms.Form):
    """ send new password form """
    username = forms.CharField(max_length=30,
            widget=forms.TextInput(attrs={'class': "required" }))

    def __init__(self, data=None, files=None, auto_id='id_%s', prefix=None, 
            initial=None):
        super(EmailPasswordForm, self).__init__(data, files, auto_id, 
                prefix, initial)
        self.user_cache = None


    def clean_username(self):
        """ get user for this username """
        if 'username' in self.cleaned_data:
            try:
                self.user_cache = User.objects.get(
                        username = self.cleaned_data['username'])
            except:
                raise forms.ValidationError(_("Incorrect username."))
        return self.cleaned_data['username']
