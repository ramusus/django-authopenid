from django.conf.urls import patterns, include, url
from django.contrib import admin

admin.autodiscover()

urlpatterns = patterns('',
    url(r'^$', 'example.views.home', name='home'),
    url(r'^account/', include('django_authopenid.urls')),

    url(r'^admin/', include(admin.site.urls)),
)
