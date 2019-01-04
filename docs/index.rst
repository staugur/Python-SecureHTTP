.. Python-SecureHTTP documentation master file, created by
   sphinx-quickstart on Fri Jan  4 14:49:36 2019.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

=================
Python-SecureHTTP
=================

.. currentmodule:: SecureHTTP

通过使用RSA+AES让HTTP传输更加安全，即C/S架构的加密通信! (Make HTTP transmissions more secure via RSA+AES, encrypted communication for C/S architecture.)


-----------------
API Documentation
-----------------

.. automodule:: SecureHTTP
    :members: RSAEncrypt, RSADecrypt, AESEncrypt, AESDecrypt, EncryptedCommunicationClient, EncryptedCommunicationServer, generate_rsa_keys
    :undoc-members:
    :show-inheritance:
    :noindex:

-----------------
CLI Documentation
-----------------

命令行工具用于辅助性功能，目前主要是用于生成RSA密钥对，有两种方法。

1. generate_rsa_keys.py
-----------------------

这是Python自身生成的RSA密钥对，此命令可以传递一个位置：密钥长度（默认1024），直接在控制台输出密钥内容，比如::

    generate_rsa_keys.py 2048

2. generate_rsa_keys.sh
-----------------------

这是使用系统OpenSSL生成的RSA密钥对，此命令可以传递一个位置：密钥长度（默认1024），在当前目录保存4个文件，分别是pkcs1格式密钥对和pkcs8密钥对，比如::

    generate_rsa_keys.sh 2048

