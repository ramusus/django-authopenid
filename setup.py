#!/usr/bin/env python
# -*- coding: utf-8 -
#
from setuptools import setup


import os
import sys

setup(
    name = 'django-authopenid',
    version = '0.9.6',
    description = 'Openid authentification application for Django',
    long_description = \
"""Django authentification application with openid using django auth contrib. Rhis application allow a user to connect to you website with a legacy account (username/password) or an openid url.""",
    author = 'Benoit Chesneau',
    author_email = 'bchesneau@gmail.com',
    license = 'BSD',
    url = 'http://code.google.com/p/django-authopenid/',
    zip_safe = False,

    classifiers = [
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Utilities',
        'Topic :: System :: Systems Administration :: Authentication/Directory'
    ],
    packages = ['django_authopenid'],
    package_data = { 'django_authopenid': [ 'templates/*.*', 'templates/authopenid/*'] },
    
    zip_safe = False,

    setup_requires = [
        'setuptools>=0.6b1',
        'python-openid'
    ]


)
