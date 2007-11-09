from django.db import models
from django.contrib.auth.models import User
from django.conf import settings

import md5, random, sys, os, time

class UserAssociation(models.Model):
    openid_url = models.CharField(blank=False, maxlength=255)
    user = models.ForeignKey(User,unique=True)
    
    def __unicode__(self):
        return "Openid %s with user %s" % (self.openid_url, self.user)
        
    class Admin:
        pass


class UserPasswordQueueManager(models.Manager):
    def get_new_confirm_key(self):
        "Returns key that isn't being used."
        # The random module is seeded when this Apache child is created.
        # Use SECRET_KEY as added salt.
        while 1:
            confirm_key = md5.new("%s%s%s%s" % (random.randint(0, sys.maxint - 1), os.getpid(), time.time(), settings.SECRET_KEY)).hexdigest()
            try:
                self.get(confirm_key=confirm_key)
            except self.model.DoesNotExist:
                break
        return confirm_key


class UserPasswordQueue(models.Model):
    user = models.ForeignKey(User, unique=True)
    new_password = models.CharField(maxlength=30)
    confirm_key = models.CharField(max_length=40)

    objects = UserPasswordQueueManager()


    def __unicode__(self):
        return self.user.username
