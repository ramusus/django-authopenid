from django.conf.urls.defaults import *


urlpatterns = patterns('',
    (r'^$', 'django.views.generic.simple.direct_to_template', {'template': 'home.html'}),
    (r'^account/', include('django_authopenid.urls')),
    #(r'^admin/', include('django.contrib.admin.urls')),
)
