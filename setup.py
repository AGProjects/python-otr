#!/usr/bin/python

import os
from distutils.core import setup, Distribution

Distribution.install_requires = None  # make distutils ignore this option that is used by setuptools when invoked from pip install


class PackageInfo(object):
    def __init__(self, info_file):
        with open(info_file) as f:
            exec(f.read(), self.__dict__)
        self.__dict__.pop('__builtins__', None)

    def __getattribute__(self, name):  # this is here to silence the IDE about missing attributes
        return super(PackageInfo, self).__getattribute__(name)


package_info = PackageInfo(os.path.join('otr', '__info__.py'))

requirements = [
    'python_application (>=2.0.0)',
    'cryptography (>=1.0)',
    'enum34',
    'gmpy2',
    'zope.interface'
]


setup(
    name=package_info.__project__,
    version=package_info.__version__,

    description=package_info.__summary__,
    long_description=open('README').read(),
    license=package_info.__license__,
    url=package_info.__webpage__,

    author=package_info.__author__,
    author_email=package_info.__email__,

    platforms=["Platform Independent"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ],

    packages=['otr'],
    provides=['otr'],
    requires=requirements,
    install_requires=[requirement.translate(None, ' ()') for requirement in requirements]
)
