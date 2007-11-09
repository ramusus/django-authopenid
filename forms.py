from django import newforms as forms
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.utils.translation import ugettext as _

import re

attrs_dict = { 'class': 'required login' }
username_re = re.compile(r'^\w+$')

class OpenidAuthForm(forms.Form):
    next = forms.CharField(max_length=255,widget=forms.HiddenInput(), required=False)
    username = forms.CharField(max_length=30,  widget=forms.widgets.TextInput(attrs=attrs_dict))
    password = forms.CharField(max_length=128, widget=forms.widgets.PasswordInput(attrs=attrs_dict))
       
    def __init__(self, data=None, files=None, auto_id='id_%s', prefix=None, initial=None):
        super(OpenidAuthForm, self).__init__(data, files, auto_id, prefix, initial)
        self.user_cache=None
            
    def clean_username(self):
        if 'username' in self.cleaned_data and 'openid_url' not in self.cleaned_data:
            if not username_re.search(self.cleaned_data['username']):
                raise forms.ValidationError(_("Usernames can only contain letters, numbers and underscores"))
            try:
                user = User.objects.get(username__exact=self.cleaned_data['username'])
            except User.DoesNotExist:
                raise forms.ValidationError(_("This username don't exist in database. Please choose another."))
            return self.cleaned_data['username']

    def clean_password(self):
        if 'username' in self.cleaned_data and 'password' in self.cleaned_data:
            self.user_cache =  authenticate(username=self.cleaned_data['username'], password=self.cleaned_data['password'])
            if self.user_cache is None:
                raise forms.ValidationError(_("Please enter a correct username and password. Note that both fields are case-sensitive."))
            elif self.user_cache.is_active == False:
                raise forms.ValidationError(_("This account is inactive."))
            return self.cleaned_data['password']

    def clean_next(self):
        if 'next' in self.cleaned_data and self.cleaned_data['next'] != "":
            next_url_re = re.compile('^/[-\w/]+$')
            if not next_url_re.match(self.cleaned_data['next']):
                raise forms.ValidationError(_('next url "%s" is invalid' % self.cleaned_data['next']))
            return self.cleaned_data['next']
            
    def get_user(self):
        return self.user_cache
            

class OpenidRegisterForm(forms.Form):
    next = forms.CharField(max_length=255,widget=forms.HiddenInput(), required=False)

    username = forms.CharField(max_length=30, widget=forms.widgets.TextInput(attrs=attrs_dict))
    email = forms.CharField(max_length=255, widget=forms.widgets.TextInput(attrs=attrs_dict))
    
    def clean_username(self):
        if 'username' in self.cleaned_data:
            if not username_re.search(self.cleaned_data['username']):
                raise forms.ValidationError(_("Usernames can only contain letters, numbers and underscores"))
            try:
                user = User.objects.get(username__exact=self.cleaned_data['username'])
            except User.DoesNotExist:
                return self.cleaned_data['username']
            raise forms.ValidationError(_("This username is already taken. Please choose another."))
            
    def clean_email(self):
        """For security reason one unique email in database"""
        if 'email' in self.cleaned_data:
            try:
                user = User.objects.get(email=self.cleaned_data['email'])
            except User.DoesNotExist:
                return self.cleaned_data['email']
            raise forms.ValidationError(_("This email is already registered in our database. Please choose another."))
 
    
class OpenidVerifyForm(forms.Form):
    next = forms.CharField(max_length=255,widget=forms.HiddenInput(), required=False)
    username = forms.CharField(max_length=30, widget=forms.widgets.TextInput(attrs=attrs_dict))
    password = forms.CharField(max_length=128, widget=forms.widgets.PasswordInput(attrs=attrs_dict))
     
    def clean_username(self):
        if 'username' in self.cleaned_data:
            if not username_re.search(self.cleaned_data['username']):
                raise forms.ValidationError(_("Usernames can only contain letters, numbers and underscores"))
            try:
                user = User.objects.get(username__exact=self.cleaned_data['username'])
            except User.DoesNotExist:
                raise forms.ValidationError(_("This username don't exist. Please choose another."))
            return self.cleaned_data['username']
            
    def clean_password(self):
        if 'username' in self.cleaned_data and 'password' in self.cleaned_data:
            self.user_cache =  authenticate(username=self.cleaned_data['username'], password=self.cleaned_data['password'])
            if self.user_cache is None:
                raise forms.ValidationError(_("Please enter a correct username and password. Note that both fields are case-sensitive."))
            elif self.user_cache.is_active == False:
                raise forms.ValidationError(_("This account is inactive."))
            return self.cleaned_data['password']
            
    def get_user(self):
        return self.user_cache


attrs_dict = { 'class': 'required' }
username_re = re.compile(r'^\w+$')

class RegistrationForm(forms.Form):
    next = forms.CharField(max_length=255,widget=forms.HiddenInput(), required=False)
    username = forms.CharField(max_length=30,
                               widget=forms.TextInput(attrs=attrs_dict),
                               label=u'Username')
    email = forms.EmailField(widget=forms.TextInput(attrs=dict(attrs_dict,
                                                               maxlength=200)),
                             label=u'Email address')
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
                raise forms.ValidationError(u'Usernames can only contain letters, numbers and underscores')
            try:
                user = User.objects.get(username__exact=self.cleaned_data['username'])
            except User.DoesNotExist:
                return self.cleaned_data['username']
            raise forms.ValidationError(u'This username is already taken. Please choose another.')

    def clean_email(self):
        if 'email' in self.cleaned_data:
            try:
                user = User.objects.get(email=self.cleaned_data['email'])
            except:
                return self.cleaned_data['email']
            raise forms.ValidationError(u'This email is already registered in our database. Please choose another.')
        return self.cleaned_data['email']
    
    def clean_password2(self):
        """
        Validates that the two password inputs match.
        
        """
        if 'password1' in self.cleaned_data and 'password2' in self.cleaned_data and \
           self.cleaned_data['password1'] == self.cleaned_data['password2']:
            return self.cleaned_data['password2']
        raise forms.ValidationError(u'You must type the same password each time')


class ChangepwForm(forms.Form):
    username = forms.CharField(max_length=30,widget=forms.HiddenInput())
    oldpw = forms.CharField(widget=forms.PasswordInput(attrs=attrs_dict))
    password1 = forms.CharField(widget=forms.PasswordInput(attrs=attrs_dict))
    password2 = forms.CharField(widget=forms.PasswordInput(attrs=attrs_dict))

    def clean_oldpw(self):
        if 'oldpw' in self.cleaned_data:
            try:
                u=User.objects.get(username=self.cleaned_data['username'])
            except:
                 raise forms.ValidationError(_("Incorrect username. What are you trying to do ..."))
                 
            if not u.check_password(self.cleaned_data['oldpw']):
                raise forms.ValidationError(_("Old password is wrong. Please enter a valid password."))
        return self.cleaned_data['oldpw']
    
    def clean_password2(self):
        """
        Validates that the two password inputs match.
        
        """
        if 'password1' in self.cleaned_data and 'password2' in self.cleaned_data and \
           self.cleaned_data['password1'] == self.cleaned_data['password2']:
            return self.cleaned_data['password2']
        raise forms.ValidationError(_("new passwords do not match each other"))
        
        
class ChangeemailForm(forms.Form):
    username = forms.CharField(max_length=30,widget=forms.HiddenInput())
    email = forms.CharField(max_length=255,widget=forms.TextInput(attrs={'class': "required validate-email" }))
    password = forms.CharField(widget=forms.PasswordInput(attrs=attrs_dict))

    def __init__(self, data=None, files=None, auto_id='id_%s', prefix=None, initial=None):
        super(ChangeemailForm, self).__init__(data, files, auto_id, prefix, initial)
        self.test_openid=False

    def clean_password(self):
        if 'password' in self.cleaned_data:
            try:
                u=User.objects.get(username=self.cleaned_data['username'])
            except:
                raise forms.ValidationError(_("Incorrect username."))
                 
            if not u.check_password(self.cleaned_data['password']):
                self.test_openid=True
        return self.cleaned_data['password']
                
class ChangeopenidForm(forms.Form):
    username = forms.CharField(max_length=30,widget=forms.HiddenInput())
    openid_url = forms.CharField(max_length=255,widget=forms.TextInput(attrs={'class': "required" }))


class DeleteForm(forms.Form):
    username = forms.CharField(max_length=30,widget=forms.HiddenInput())
    confirm = forms.CharField(widget=forms.CheckboxInput(attrs=attrs_dict))
    password = forms.CharField(widget=forms.PasswordInput(attrs=attrs_dict))

    def __init__(self, data=None, files=None, auto_id='id_%s', prefix=None, initial=None):
        super(DeleteForm, self).__init__(data, files, auto_id, prefix, initial)
        self.test_openid=False

    def clean_password(self):
        if 'password' in self.cleaned_data:
            try:
                u=User.objects.get(username=self.cleaned_data['username'])
            except:
                raise forms.ValidationError(_("Incorrect username."))
                 
            if not u.check_password(self.cleaned_data['password']):
                self.test_openid=True
        return self.cleaned_data['password']


class EmailPasswordForm(forms.Form):
    username = forms.CharField(max_length=30,widget=forms.TextInput(attrs={'class': "required" }))

    def __init__(self, data=None, files=None, auto_id='id_%s', prefix=None, initial=None):
        super(EmailPasswordForm, self).__init__(data, files, auto_id, prefix, initial)
        self.user_cache=None


    def clean_username(self):
        if 'username' in self.cleaned_data:
            try:
                self.user_cache=User.objects.get(username=self.cleaned_data['username'])
            except:
                raise forms.ValidationError(_("Incorrect username."))
        return self.cleaned_data['username']
