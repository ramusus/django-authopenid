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

from django.http import HttpResponseRedirect
from django.utils.encoding import iri_to_uri
from django.core.urlresolvers import reverse



def username_control(view_name):
    """
    decorator that test if user is authenticated and if
    username in request.path is the one used by authenticated
    user.

    if user isn't authenticated it redirect him to signin page.
    If username != username authenticated, it redirect to
    the "good" page. Url is also changed.
    """

    def _username_controller(view_func):
        def _username_controlled(request, *args, **kwargs):
            response = view_func(request, *args, **kwargs)
            username = None
            if 'username' in kwargs:
                username = kwargs['username']

            if not username or username!=request.user.username: 
                kwargs['username'] = request.user.username
                redirect_to=iri_to_uri(reverse(view_name, kwargs=kwargs))
                return HttpResponseRedirect(redirect_to)

            return response
        return _username_controlled

    return _username_controller
