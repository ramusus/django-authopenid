from django.contrib.auth.models import User
from django.http import HttpResponseRedirect
from django.utils.encoding import smart_str, iri_to_uri
from django.utils.translation import ugettext as _
from django.utils.http import urlquote_plus
from django.core.urlresolvers import resolve,reverse

from django_openidconsumer.views import get_url_host


def username_test(view_func, view_name='django_authopenid.views.account_settings'):

    def decorate(request, *args, **kwargs):
        username = None
        if 'username' in kwargs:
            username = kwargs['username']

        if not request.user.is_authenticated():
            msg = _("In order to change settings for %s, you should be authenticated." % username)
            redirect_to = "%s?next=%s&msg=%s" % (
                reverse('django_authopenid.views.signin'), 
                request.path, urlquote_plus(msg))
            return HttpResponseRedirect(redirect_to)

        if not username or username!=request.user.username: 
            kwargs['username'] = request.user.username
            redirect_to=iri_to_uri(reverse(view_name, kwargs=kwargs))
            return HttpResponseRedirect(redirect_to)

        return view_func(request, *args, **kwargs)
    return decorate


