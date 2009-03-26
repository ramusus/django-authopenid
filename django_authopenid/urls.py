# -*- coding: utf-8 -*-
from django.conf.urls.defaults import patterns, url
from django.views.generic.simple import direct_to_template

# views
from django.contrib.auth import views as auth_views
from django_authopenid import views as oid_views
from registration import views as reg_views


urlpatterns = patterns('',
    # django registration activate
    url(r'^activate/(?P<activation_key>\w+)/$', reg_views.activate, name='registration_activate'),
    
    # user profile
    url(r'^password/$',oid_views.password_change, name='auth_password_change'),
    
    # manage account registration
    url(r'^register/$', oid_views.register, name='user_register'),
    url(r'^signin/$', oid_views.signin, name='user_signin'),
    url(r'^signout/$', oid_views.signout, name='user_signout'),
    url(r'^signin/complete/$', oid_views.complete_signin, name='user_complete_signin'),
    url(r'^signup/$', reg_views.register, name='registration_register'),
    url(r'^signup/complete/$',direct_to_template, 
        {'template': 'registration/registration_complete.html'},
        name='registration_complete'),
    
    # yadis uri
    url(r'^yadis.xrdf$', oid_views.xrdf, name='oid_views.yadis_xrdf'),
)
