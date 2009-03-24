
## version 1.0a

### BREAKING CHANGE: 
- need django latest trunk or 1.1 when released
- no more legacy user creation and account managementt. Developpers could use django-registration or anything else

### OTHERS:

- `django_authopenid.util` is now deprecated and renamed to `django.utils`
- default django openid store is now in `django_authopenid.openid_store`
- you could now set a custom openid store by settings settings.OPENID_STORE


