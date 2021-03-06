.. Python-SecureHTTP documentation master file, created by
   sphinx-quickstart on Fri Jan  4 14:49:36 2019.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

=================
Python-SecureHTTP
=================

.. toctree::
    :maxdepth: 1

.. currentmodule:: SecureHTTP

通过使用RSA+AES让HTTP传输更加安全，即C/S架构的加密通信! (Make HTTP transmissions more secure via RSA+AES, encrypted communication for C/S architecture.)

|PyPI| |Pyversions| |implementation|

------------------
安装(Installation)
------------------

*使用pip安装*：

.. code:: bash

    # 正式版(Release)
    $ pip install -U SecureHTTP
    # 开发版(Dev)
    $ pip install -U git+https://github.com/staugur/Python-SecureHTTP.git@master

*关于依赖库*：

    SecureHTTP依赖pycryptodomex。

    PyCryptodome是PyCrypto的一个分支，它为PyCrypto的最后一个正式版本（2.6.1）带来了一些增强功能，如支持pypy。
    PyCryptodomex即PyCryptodome，区别在于导入包名不同，前者导入包名是Cryptodome，后者是Crypto(同pycrypto)。

    **注意：v0.5.0开始，已经弃用PyCrypto/PyCryptodome！**


---------------
测试用例(Test)
---------------

*温馨提示：完整的测试要求安装php、go以便运行多语言测试*

.. code:: bash

    $ git clone https://github.com/staugur/Python-SecureHTTP && cd Python-SecureHTTP
    $ make dev && make test

---------------
简单示例(Demo)
---------------

1. AES加密、解密

   .. code:: python

       from SecureHTTP import AESEncrypt, AESDecrypt
       # 加密后的密文
       ciphertext = AESEncrypt('ThisIsASecretKey', 'Hello World!', output="hex")
       # 解密后的明文
       plaintext = AESDecrypt("ThisIsASecretKey", ciphertext, input="hex)

2. RSA加密、解密

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


--------------------------------------------------
加密传输通信的流程(Encrypted Transmission Process)
--------------------------------------------------


总体流程：客户端上传数据加密 ==> 服务端获取数据解密 ==> 服务端返回数据加密 ==> 客户端获取数据解密

NO.1 客户端上传数据加密流程::

        1. 客户端随机产生一个16位的字符串，用以之后AES加密的秘钥，AESKey。
        2. 使用RSA对AESKey进行公钥加密，RSAKey。
        3. 参数加签，参考"加签、验签规则流程"。
        4. 将明文的要上传的数据包(字典/Map)转为Json字符串，使用AESKey加密，得到JsonAESEncryptedData。
        5. 封装为{key : RSAKey, value : JsonAESEncryptedData}的字典上传服务器，服务器只需要通过key和value，然后解析，获取数据即可。

NO.2 服务端获取数据解密流程::

        1. 获取到RSAKey后用服务器私钥解密，获取到AESKey
        2. 获取到JsonAESEncriptedData，使用AESKey解密，得到明文的客户端上传上来的数据。
        3. 验签，参考"加签、验签规则流程"
        4. 返回明文数据

NO.3 服务端返回数据加密流程::

        1. 将要返回给客户端的数据(字典/Map)进行加签并将签名附属到数据中
        2. 上一步得到的数据转成Json字符串，用AESKey加密处理，记为AESEncryptedResponseData
        3. 封装数据{data : AESEncryptedResponseData}的形式返回给客户端

NO.4 客户端获取数据解密流程::

        1. 客户端获取到数据后通过key为data得到服务器返回的已经加密的数据AESEncryptedResponseData
        2. 对AESEncryptedResponseData使用AESKey进行解密，得到明文服务器返回的数据。

----------------------------------
加签、验签规则流程(Signature Rule)
----------------------------------

@加签、验签规则：

        加签，即 ``EncryptedCommunicationClient.clientEncrypt`` 和 ``EncryptedCommunicationServer.serverEncrypt`` 方法，签名已经内置，支持传入 ``signIndex`` 参数生成不同签名。

        验签，即 ``EncryptedCommunicationClient.clientDecrypt`` 和 ``EncryptedCommunicationServer.serverDecrypt`` 方法，验签已经内置，验签失败触发 ``SignError`` 错误。

        signIndex::

            False, 不签名、不验签
            None, 签名数据中所有字段(目前版本，如果嵌套了无序数据类型，可能会验签失败)
            str, 指定参与签名的字段，格式是"key1,key2"，这是目前建议的一种方法，只针对部分核心字段签名和验签

@签名步骤：

        1. 构造规范化的请求字符串

            按照字母升序，对参数名称进行排序。

        2. 排序后的参数以"参数名=值&"的形式连接，其中参数名和值要进行URL编码，使用UTF-8字符集，编码规则是::

            2.1 对于字符 A-Z、a-z、0-9以及字符“-”、“_”、“.”、“~”不编码；
            2.2 对于其他字符编码成“%XY”的格式，其中XY是字符对应ASCII码的16进制表示。比如英文的双引号（”）对应的编码就是%22.
            2.3 英文空格（ ）编码为%20，而不是加号（+）。

        3. 对以上规范化的字符串使用摘要算法得到签名

@验签步骤：

        验签同签名类似。

@注意事项：

        签名规则可以参考阿里云API签名

-----------------
CLI Documentation
-----------------

命令行工具用于辅助性功能，目前主要是用于生成RSA密钥对，有两种方法。

1. generate_rsa_keys.py
-----------------------

这是Python自身生成的RSA密钥对，它支持输出到控制台或写入文件、设置私钥密码等，请查看命令帮助::

    # generate_rsa_keys.py -h
    usage: generate_rsa_keys.py [-h] [-v] [-l {1024,2048,3072,4096}]
                            [-p PASSPHRASE] [-w]

    optional arguments:
      -h, --help            show this help message and exit
      -v, --version         Print the SecureHTTP Version
      -l {1024,2048,3072,4096}, --length {1024,2048,3072,4096}
                            Key length, default is 2048.
      -p PASSPHRASE, --passphrase PASSPHRASE
                            The pass phrase used for protecting the private key.
      -w, --write           Write a key pair file in PEM format

2. generate_rsa_keys.sh
-----------------------

这是使用系统OpenSSL生成的RSA密钥对，此命令可以传递一个位置：密钥长度（默认1024），在当前目录保存4个文件，分别是pkcs1格式密钥对和pkcs8密钥对，比如::

    generate_rsa_keys.sh 2048


SecureHTTP.js
-------------

请参考： `SecureHTTP.js <https://docs.saintic.com/securehttp.js>`_

-----------------
API Documentation
-----------------

PS:
    接口中函数返回值，正常情况下，Python2.7返回unicode，Python3.x返回str。

    函数参数要求字符串的，一般建议py2中使用unicode，py3中使用bytes，请注意编码问题。

    另，RSADecrypt解密中，新增一个sentinel参数，一个挺重要的解密失败的标记，关于此参数的建议，请参考：`Pycryptodomex接口文档 <https://www.pycryptodome.org/en/latest/src/cipher/pkcs1_v1_5.html?hide=0#Crypto.Cipher.PKCS1_v1_5.PKCS115_Cipher.decrypt>`_，注意文档中 ``Warning`` 部分。

.. automodule:: SecureHTTP
    :members: RSAEncrypt, RSADecrypt, AESEncrypt, AESDecrypt, EncryptedCommunicationClient, EncryptedCommunicationServer, generate_rsa_keys, SignError, AESError, RSAError
    :undoc-members:
    :show-inheritance:
    :noindex:

-------------------
更新日志(CHANGELOG)
-------------------

.. include:: ../CHANGELOG.rst


.. |PyPI| image:: https://img.shields.io/pypi/v/SecureHTTP.svg?style=popout
   :target: https://pypi.org/project/SecureHTTP

.. |Pyversions| image:: https://img.shields.io/pypi/pyversions/SecureHTTP.svg
   :target: https://pypi.org/project/SecureHTTP

.. |implementation| image:: https://img.shields.io/pypi/implementation/SecureHTTP.svg
   :target: https://pypi.org/project/SecureHTTP
