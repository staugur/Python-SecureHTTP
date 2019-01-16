# -*- coding: utf-8 -*-
"""
Python-SecureHTTP
=================

让HTTP传输更加安全，C/S架构的加密通信!(Make HTTP transmissions more secure, encrypted communication for C/S architecture.)


使用概述(Overview)
~~~~~~~~~~~~~~~~~~

安装(Installation)

.. code:: bash

    $ pip install Python-SecureHTTP

示例(Demo)

`点击这里查看简单示例 <https://github.com/staugur/Python-SecureHTTP/blob/master/examples/Demo/>`_

文档(Documentation)
~~~~~~~~~~~~~~~~~~~

`中文 <https://python-securehttp.readthedocs.io/zh_CN/latest/>`__
"""

import os
import re
import ast
import unittest
from setuptools import setup, Command


def test_suite():
    test_loader = unittest.TestLoader()
    test_suite = test_loader.discover('tests', pattern='test_*.py')
    return test_suite


def _get_version():
    version_re = re.compile(r'__version__\s+=\s+(.*)')

    with open('SecureHTTP.py', 'rb') as fh:
        version = ast.literal_eval(version_re.search(fh.read().decode('utf-8')).group(1))

    return str(version)


def _get_author():
    author_re = re.compile(r'__author__\s+=\s+(.*)')
    mail_re = re.compile(r'(.*)\s<(.*)>')

    with open('SecureHTTP.py', 'rb') as fh:
        author = ast.literal_eval(author_re.search(fh.read().decode('utf-8')).group(1))

    return (mail_re.search(author).group(1), mail_re.search(author).group(2))


class PublishCommand(Command):

    description = "Publish a new version to pypi"

    user_options = [
        # The format is (long option, short option, description).
        ("test", None, "Publish to test.pypi.org"),
        ("release", None, "Publish to pypi.org"),
    ]

    def initialize_options(self):
        """Set default values for options."""
        self.test = False
        self.release = False

    def finalize_options(self):
        """Post-process options."""
        if self.test:
            print("V%s will publish to the test.pypi.org" % version)
        elif self.release:
            print("V%s will publish to the pypi.org" % version)

    def run(self):
        """Run command."""
        os.system("pip install -U setuptools twine wheel")
        os.system("rm -rf build/ dist/ Python_SecureHTTP.egg-info/")
        os.system("python setup.py sdist bdist_wheel")
        if self.test:
            os.system("twine upload --repository-url https://test.pypi.org/legacy/ dist/*")
        elif self.release:
            os.system("twine upload dist/*")
        os.system("rm -rf build/ dist/ Python_SecureHTTP.egg-info/")
        if self.test:
            print("V%s publish to the test.pypi.org successfully" % version)
        elif self.release:
            print("V%s publish to the pypi.org successfully" % version)
        exit()


version = _get_version()
(author, email) = _get_author()
setup(
    name='SecureHTTP',
    version=version,
    url='https://github.com/staugur/Python-SecureHTTP',
    download_url="https://github.com/staugur/Python-SecureHTTP/releases/tag/v%s" % version,
    license='MIT',
    author=author,
    author_email=email,
    keywords=["RSA", "AES", "MD5", "HTTP"],
    description='Make HTTP transmissions more secure, encrypted communication for C/S architecture.',
    long_description=__doc__,
    test_suite='setup.test_suite',
    py_modules=['SecureHTTP', ],
    scripts=["generate_rsa_keys.sh"],
    entry_points={
        'console_scripts': [
            'generate_rsa_keys.py = SecureHTTP:generate_rsa_keys'
        ]
    },
    platforms='any',
    install_requires=[
        'rsa>=4.0',
        'pycryptodome>=3.7.2'
    ],
    tests_require=["flask>0.9"],
    cmdclass={
        'publish': PublishCommand,
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
