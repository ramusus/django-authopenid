# -*- coding: utf-8 -*-

import time
import urllib

from django.conf import settings
from django.http import str_to_unicode
from openid.extensions import sreg

try: # needed for some linux distributions like debian
    from openid.yadis import xri
except ImportError:
    from yadis import xri

__all__ = ['OpenID', 'from_openid_response', 'clean_next']

class OpenID(object):
    def __init__(self, openid_, issued, attrs=None, sreg_=None):
        self.openid = openid_
        self.issued = issued
        self.attrs = attrs or {}
        self.sreg = sreg_ or {}
        self.is_iname = (xri.identifierScheme(openid_) == 'XRI')
    
    def __repr__(self):
        return '<OpenID: %s>' % self.openid
    
    def __str__(self):
        return self.openid

DEFAULT_NEXT = getattr(settings, 'OPENID_REDIRECT_NEXT', '/')
def clean_next(next):
    if next is None:
        return DEFAULT_NEXT
    next = str_to_unicode(urllib.unquote(next), 'utf-8')
    next = next.strip()
    if next.startswith('/'):
        return next
    return DEFAULT_NEXT


def from_openid_response(openid_response):
    """ return openid object from response """
    issued = int(time.time())
    sreg_resp = sreg.SRegResponse.fromSuccessResponse(openid_response) \
            or []
    
    return OpenID(
        openid_response.identity_url, issued, openid_response.signed_fields, 
         dict(sreg_resp)
    )