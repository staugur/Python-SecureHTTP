.. Python-SecureHTTP documentation master file, created by
   sphinx-quickstart on Fri Jan  4 14:49:36 2019.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

=================
Python-SecureHTTP
=================

.. currentmodule:: SecureHTTP

通过使用RSA+AES让HTTP传输更加安全，即C/S架构的加密通信! (Make HTTP transmissions more secure via RSA+AES, encrypted communication for C/S architecture.)


加密传输通信的流程
-------------------

::

    客户端上传数据加密 ==> 服务端获取数据解密 ==> 服务端返回数据加密 ==> 客户端获取数据解密

    NO.1 客户端上传数据加密流程::

        1. 客户端随机产生一个16位的字符串，用以之后AES加密的秘钥，AESKey。
        2. 使用RSA对AESKey进行公钥加密，RSAKey。
        3. 参数加签，规则是：对所有请求或提交的字典参数按key做升序排列并用"参数名=参数值&"形式连接。
        4. 将明文的要上传的数据包(字典/Map)转为Json字符串，使用AESKey加密，得到JsonAESEncryptedData。
        5. 封装为{key : RSAKey, value : JsonAESEncryptedData}的字典上传服务器，服务器只需要通过key和value，然后解析，获取数据即可。

    NO.2 服务端获取数据解密流程::

        1. 获取到RSAKey后用服务器私钥解密，获取到AESKey
        2. 获取到JsonAESEncriptedData，使用AESKey解密，得到明文的客户端上传上来的数据。
        3. 验签
        4. 返回明文数据

    NO.3 服务端返回数据加密流程::

        1. 将要返回给客户端的数据(字典/Map)进行加签并将签名附属到数据中
        2. 上一步得到的数据转成Json字符串，用AESKey加密处理，记为AESEncryptedResponseData
        3. 封装数据{data : AESEncryptedResponseData}的形式返回给客户端

    NO.4 客户端获取数据解密流程::

        1. 客户端获取到数据后通过key为data得到服务器返回的已经加密的数据AESEncryptedResponseData
        2. 对AESEncryptedResponseData使用AESKey进行解密，得到明文服务器返回的数据。

简单示例
---------

`点击这里查看简单示例 <https://github.com/staugur/Python-SecureHTTP/blob/master/examples/Demo/>`_


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

