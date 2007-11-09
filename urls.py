from django.conf.urls.defaults import patterns

urlpatterns = patterns('',
     # manage account registration
    (r'^signin/$', 'django_authopenid.views.signin'),
    (r'^signout/$', 'django_authopenid.views.signout'),
    (r'^complete/$', 'django_authopenid.views.complete_signin'),
    (r'^register/$', 'django_authopenid.views.register'),
    (r'^signup/$', 'django_authopenid.views.signup'),
    (r'^signup/$', 'django_authopenid.views.signup'),
    ('^sendpw/$', 'django_authopenid.views.sendpw'),

    # manage account settings
    (r'^(?P<username>\w+)/$', 'django_authopenid.views.account_settings'),
    (r'^$', 'django_authopenid.views.account_settings'),
    (r'^(?P<username>\w+)/changepw/$', 'django_authopenid.views.changepw'),
    (r'^(?P<username>\w+)/changeemail/$', 'django_authopenid.views.changeemail'),
    (r'^(?P<username>\w+)/changeopenid/$', 'django_authopenid.views.changeopenid'),
    (r'^(?P<username>\w+)/delete/$', 'django_authopenid.views.delete'),
    (r'^sendpw/confirm/$', 'django_authopenid.views.confirmchangepw'),

)
