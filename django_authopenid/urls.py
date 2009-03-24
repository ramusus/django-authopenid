# -*- coding: utf-8 -*-
from django.conf.urls.defaults import patterns, url
from django.utils.translation import ugettext as _

urlpatterns = patterns('django_authopenid.views',
    # yadis rdf
    url(r'^yadis.xrdf$', 'xrdf', name='yadis_xrdf'),
     # manage account registration
    url(r'^signin/$', 'signin', name='user_signin'),
    url(r'^signout/$', 'signout', name='user_signout'),
    url(r'^signin/complete/$', 'complete_signin', name='user_complete_signin'),
    url(r'^register/$', 'register', name='user_register'),
)
