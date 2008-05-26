from django.conf.urls.defaults import *

urlpatterns = patterns('',
    (r'^account/', include('django_authopenid.urls')),
    (r'^admin/', include('django.contrib.admin.urls')),
)
