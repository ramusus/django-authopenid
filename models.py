# -*- coding: utf-8 -*-
from django.db import models
from django.contrib.auth.models import User
from django.conf import settings

import md5, random, sys, os, time

class Nonce(models.Model):
    server_url = models.CharField(maxlength=255)
    timestamp = models.IntegerField()
    salt = models.CharField(max_length=40)
    
    def __unicode__(self):
        return u"Nonce: %s" % self.id

    
class Association(models.Model):
    server_url = models.TextField(maxlength=2047)
    handle = models.CharField(maxlength=255)
    secret = models.TextField(maxlength=255) # Stored base64 encoded
    issued = models.IntegerField()
    lifetime = models.IntegerField()
    assoc_type = models.TextField(maxlength=64)
    
    def __unicode__(self):
        return u"Association: %s, %s" % (self.server_url, self.handle)

class UserAssociation(models.Model):
    """ 
    model to manage association between openid and user 
    """
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
    """
    model for new password queue.
    """
    user = models.ForeignKey(User, unique=True)
    new_password = models.CharField(maxlength=30)
    confirm_key = models.CharField(max_length=40)

    objects = UserPasswordQueueManager()


    def __unicode__(self):
        return self.user.username
