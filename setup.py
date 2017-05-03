#!/usr/bin/env python
import os
import sys
from setuptools import setup
from pkg_resources import resource_filename

# depending on your execution context the version file
# may be located in a different place!
vsn_path = resource_filename(__name__, 'cryptorito/version')
if not os.path.exists(vsn_path):
    vsn_path = resource_filename(__name__, 'version')
    if not os.path.exists(vsn_path):
        print("%s is missing" % vsn_path)
        sys.exit(1)

setup(name='cryptorito',
      version=open(vsn_path, 'r').read(),
      description='Very lightweight wrapper around GPG2 and Keybase',
      author='Jonathan Freedman',
      author_email='jonathan.freedman@autodesk.com',
      license='MIT',
      url='https://github.com/autodesk/cryptorito',
      install_requires=['requests'],
      include_package_data=True,
      packages=['cryptorito'],
      package_data={'cryptorito':['version']}
     )
