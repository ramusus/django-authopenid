# -*- coding: utf-8 -*-
from django.conf.urls.defaults import patterns, url
from django.utils.translation import ugettext as _

from django.contrib.auth import views as auth_views
from django_authopenid import views as oid_views

urlpatterns = patterns('',
    # yadis rdf
    url(r'^yadis.xrdf$', oid_views.xrdf, name='oid_views.yadis_xrdf'),
    
    # user profile
    url(r'^password/$',oid_views.password_change, name='auth_password_change'),
    
    # manage account registration
    url(r'^register/$', oid_views.register, name='user_register'),
    url(r'^signin/$', oid_views.signin, name='user_signin'),
    url(r'^signout/$', oid_views.signout, name='user_signout'),
    url(r'^signin/complete/$', oid_views.complete_signin, name='user_complete_signin'),
  
)
