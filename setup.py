# -*- coding: utf-8 -*-
# Copyright 2007, 2008,2009 by Benoît Chesneau <benoitc@e-engura.org>
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
try:
    from setuptools import setup, find_packages
except ImportError:
    import ez_setup
    ez_setup.use_setuptools()
    from setuptools import setup, find_packages

import os
import sys

data_files = []
for dir, dirs, files in os.walk('django_authopenid'):
    for i, dirname in enumerate(dirs):
        if dirname.startswith('.'): del dirs[i]
        
    data_files.append((dir, [os.path.join(dir, file_) for file_ in files]))

setup(
    name = 'django-authopenid',
    version = '1.0a',
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
    packages = find_packages(),
    data_files = data_files,
    include_package_data = True,
    
    setup_requires = [
        'setuptools>=0.6c7',
    ],

    install_requires = [
        'python-openid',
        'django-registration'
    ],


)
