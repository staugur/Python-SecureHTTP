# -*- coding: utf-8 -*-
"""
Python-SecureHTTP
=================

让HTTP传输更加安全，C/S架构的加密通信!(Make HTTP transmissions more secure, encrypted communication for C/S architecture.)


使用概述(Overview)
~~~~~~~~~~~~~~~~~~

**安装(Installation)**

.. code:: bash

    $ pip install -U SecureHTTP

**示例代码(Examples)**


1. RSA加密、解密

   .. code:: python

       from SecureHTTP import AESEncrypt, AESDecrypt
       # 加密后的密文
       ciphertext = AESEncrypt('ThisIsASecretKey', 'Hello World!')
       # 解密后的明文
       plaintext = AESDecrypt("ThisIsASecretKey", ciphertext)

2. AES加密、解密

   .. code:: python

       from SecureHTTP import RSAEncrypt, RSADecrypt, generate_rsa_keys
       # 生成密钥对
       (pubkey, privkey) = generate_rsa_keys(incall=True)
       # 加密后的密文
       ciphertext = RSAEncrypt(pubkey, 'Hello World!')
       # 解密后的明文
       plaintext = RSADecrypt(privkey, ciphertext)

3. C/S加解密示例： `点此查看以下模拟代码的真实WEB环境示例 <https://github.com/staugur/Python-SecureHTTP/blob/master/examples/Demo/>`__

   .. code:: python

       # 模拟C/S请求
       from SecureHTTP import EncryptedCommunicationClient, EncryptedCommunicationServer, generate_rsa_keys
       post = {u'a': 1, u'c': 3, u'b': 2, u'data': ["a", 1, None]}
       resp = {u'msg': None, u'code': 0}
       # 生成密钥对
       (pubkey, privkey) = generate_rsa_keys(incall=True)
       # 初始化客户端类
       client = EncryptedCommunicationClient(pubkey)
       # 初始化服务端类
       server = EncryptedCommunicationServer(privkey)
       # NO.1 客户端加密数据
       c1 = client.clientEncrypt(post)
       # NO.2 服务端解密数据
       s1 = server.serverDecrypt(c1)
       # NO.3 服务端返回加密数据
       s2 = server.serverEncrypt(resp)
       # NO.4 客户端获取返回数据并解密
       c2 = client.clientDecrypt(s2)
       # 以上四个步骤即完成一次请求/响应

4. B/S加解密示例： `前端使用AES+RSA加密，后端解密 <https://github.com/staugur/Python-SecureHTTP/tree/master/examples/BS-RSA>`__


文档(Documentation)
~~~~~~~~~~~~~~~~~~~

`中文(Chinese) <https://python-securehttp.readthedocs.io/zh_CN/latest/>`__
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
    license='BSD 3-Clause',
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
        'pycryptodomex>=3.7.2'
    ],
    tests_require=["flask>0.9", "rsa>=4.0"],
    cmdclass={
        'publish': PublishCommand,
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
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
