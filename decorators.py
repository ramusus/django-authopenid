"""
 Copyright 2007 Benoît Chesneau 
 Licensed under the Apache License, Version 2.0 (the "License"); 
 you may not use this file except in compliance with the License. 
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0 
 
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""

from django.contrib.auth.models import User
from django.http import HttpResponseRedirect
from django.utils.encoding import smart_str, iri_to_uri
from django.utils.translation import ugettext as _
from django.utils.http import urlquote_plus
from django.core.urlresolvers import resolve,reverse

from django_openidconsumer.views import get_url_host


def username_test(view_func, view_name='django_authopenid.views.account_settings'):
    """
    decorator that test if user is authenticated and if
    username in request.path is the one used by authenticated
    user.

    if user isn't authenticated it redirect him to signin page.
    If username != username authenticated, it redirect to
    the "good" page. Url is also changed.
    """

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


