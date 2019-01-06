# -*- coding: utf-8 -*-
"""
    Python-SecureHTTP
    ~~~~~~~~~~~~~~~~~

    关于通信过程加密算法的说明：

    1. AES加解密::

        模式：CBC
        密钥长度：128位
        密钥key和初始偏移向量iv一致
        补码方式：PKCS5Padding
        加密结果编码方式：十六进制

    2. RSA加解密::

        算法：RSA
        填充：RSA_PKCS1_PADDING
        密钥格式：符合PKCS#1规范，密钥对采用PEM形式

    3. 签名::

        对请求参数或数据排序后再使用MD5签名

    :copyright: (c) 2018 by staugur.
    :license: MIT, see LICENSE for more details.
"""

import re
import sys
import rsa
import json
import time
import copy
import hashlib
import base64
from operator import mod
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

__version__ = "0.1.0"
__author__ = "staugur <staugur@saintic.com>"
__all__ = ["RSAEncrypt", "RSADecrypt", "AESEncrypt", "AESDecrypt", "EncryptedCommunicationClient", "EncryptedCommunicationServer", "generate_rsa_keys"]


PY2 = sys.version_info[0] == 2
if PY2:
    string_types = (str, unicode)
    public_key_prefix = u"-----BEGIN RSA PUBLIC KEY-----"
else:
    string_types = (str,)
    public_key_prefix = b"-----BEGIN RSA PUBLIC KEY-----"


def generate_rsa_keys(length=1024, incall=False):
    """生成RSA所需的公钥和私钥，公钥格式pkcs8，私钥格式pkcs1。

    :param length: int: 指定密钥长度，默认1024，需要更强加密可设置为2048

    :param incall: bool: 是否内部调用，默认False表示提供给脚本调用直接打印密钥，True不打印密钥改为return返回

    :returns: tuple(public_key, private_key)
    """
    if not incall:
        args = sys.argv[1:]
        if args:
            try:
                length = int(args[0])
            except:
                pass
        print("\033[1;33mGenerating RSA private key, %s bit long modulus.\n\033[0m" % length)
        startTime = time.time()
    # 开始生成
    random_generator = Random.new().read
    key = RSA.generate(length, random_generator)
    pub_key = key.publickey()
    public_key = pub_key.exportKey("PEM", pkcs=8)
    private_key = key.exportKey("PEM", pkcs=1)
    # 生成完毕
    if not incall:
        print("\033[1;32mSuccessfully generated, with %0.2f seconds.\nPlease save your private key and don't lose it!\n\033[0m" % float(time.time() - startTime))
        print("\033[1;31mRSA PublicKey for PKCS#8:\033[0m\n%s" % public_key)
        print("\n\033[1;31mRSA PrivateKey for PKCS#1:\033[0m\n%s" % private_key)
    else:
        return (public_key, private_key)


def RSAEncrypt(pubkey, plaintext):
    """RSA公钥加密

    :param pubkey: str: pkcs1或pkcs8格式公钥

    :param plaintext: str: 准备加密的文本消息

    :returns: base64编码的字符串
    """
    if pubkey and pubkey.startswith(public_key_prefix):
        pubkey = rsa.PublicKey.load_pkcs1(pubkey)
    else:
        # load_pkcs1_openssl_pem可以加载openssl生成的pkcs1公钥(实为pkcs8格式)
        pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(pubkey)
    ciphertext = rsa.encrypt(plaintext, pubkey)
    return base64.b64encode(ciphertext)


def RSADecrypt(privkey, ciphertext):
    """RSA私钥解密

    :param privkey: str: pkcs1格式私钥

    :param ciphertext: str: 已加密的消息

    :returns: 消息原文
    """
    privkey = rsa.PrivateKey.load_pkcs1(privkey)
    plaintext = rsa.decrypt(base64.b64decode(ciphertext), privkey)
    return plaintext


def AESEncrypt(key, plaintext):
    """AES加密
    :param key: str: 16位的密钥串

    :param plaintext: str: 将加密的明文消息

    :returns: str,unicode: 加密后的十六进制
    """
    if key and isinstance(key, string_types) and mod(len(key), 16) == 0 and plaintext and isinstance(plaintext, string_types):
        def PADDING(s): return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)
        generator = AES.new(key, AES.MODE_CBC, key[:AES.block_size])  # 这里的key 和IV 一样 ，可以按照自己的值定义
        ciphertext = generator.encrypt(PADDING(plaintext))
        crypted_str = base64.b64encode(ciphertext)
        return crypted_str.decode()


def AESDecrypt(key, ciphertext):
    """AES解密
    :param key: str: 16位的密钥串

    :param ciphertext: str,unicode: 已加密的十六进制数据密文

    :returns: str,bool(False): 返回False时说明解密失败，成功则返回数据
    """
    if key and isinstance(key, string_types) and mod(len(key), 16) == 0 and ciphertext and isinstance(ciphertext, string_types):
        generator = AES.new(key, AES.MODE_CBC, key[:AES.block_size])
        ciphertext += (len(ciphertext) % 4) * '='
        decrpyt_bytes = base64.b64decode(ciphertext)
        msg = generator.decrypt(decrpyt_bytes)
        # 去除解码后的非法字符
        try:
            result = re.compile('[\\x00-\\x08\\x0b-\\x0c\\x0e-\\x1f\n\r\t]').sub('', msg.decode())
        except Exception:
            return False
        return result


class EncryptedCommunicationMix(object):
    """加密传输通信基类。

    此类封装加密通信过程中所需函数，包括RSA、AES、MD5等，加密传输整个流程是::

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
    """

    def get_current_timestamp(self):
        """ 获取本地时间戳(10位): Unix timestamp：是从1970年1月1日（UTC/GMT的午夜）开始所经过的秒数，不考虑闰秒 """
        return int(time.time())

    def md5(self, message):
        """MD5签名

        :params message: str,unicode,bytes:

        :returns: str: Signed message
        """
        return hashlib.md5(message).hexdigest()

    def genAesKey(self):
        """生成AES密钥：32位"""
        return self.md5(Random.new().read(AES.block_size))

    def sign(self, parameters, index=None):
        """ 参数签名

        :param parameters: dict: 请求参数或提交的数据

        :param index: tuple,list: 参与排序加签的键名，None时表示不加签

        :returns: str: md5 message
        """
        if not isinstance(parameters, dict):
            return
        if index:
            if isinstance(index, (tuple, list)):
                data = dict()
                for k in index:
                    data[k] = parameters[k]
                parameters = data
            else:
                return
        else:
            return self.md5("&".join(sorted(parameters.keys())))
        # NO.1 参数排序
        _my_sorted = sorted(parameters.items(), key=lambda parameters: parameters[0])
        # NO.2 排序后拼接字符串
        canonicalizedQueryString = ''
        for (k, v) in _my_sorted:
            canonicalizedQueryString += '{}={}&'.format(k, v)
        print("sorted: %s" %canonicalizedQueryString)
        # NO.3 加密返回签名: Signature
        return self.md5(canonicalizedQueryString)


class EncryptedCommunicationClient(EncryptedCommunicationMix):
    """客户端：主要是公钥加密"""

    def clientEncrypt(self, AESKey, pubkey, post):
        """客户端发起加密请求通信 for NO.1

        :param AESKey: str: AES密钥，使用genAesKey方法生成

        :param pubkey: str: RSA的pkcs1或pkcs8格式公钥

        :param post: dict: 请求的数据

        :returns: dict: {key=RSAKey, value=加密数据}
        """
        # 深拷贝post
        postData = copy.deepcopy(post)
        # 使用RSA公钥加密AES密钥获取RSA密文作为密钥
        RSAKey = RSAEncrypt(pubkey, AESKey)
        # 对请求数据签名
        SignData = self.sign(postData)
        # 对请求数据填充额外信息
        postData.update(__meta__=dict(Signature=SignData, Timestamp=self.get_current_timestamp(), SignatureVersion="v1", SignatureMethod="MD5"))
        #  使用AES加密请求数据
        JsonAESEncryptedData = AESEncrypt(AESKey, json.dumps(postData))
        return dict(key=RSAKey, value=JsonAESEncryptedData)

    def clientDecrypt(self, AESKey, encryptedRespData):
        """客户端获取服务端返回的加密数据并解密 for NO.4

        :param AESKey: str: 之前生成的AESKey

        :param encryptedRespData: dict: 服务端返回的加密数据，其格式应该是 {data: AES加密数据}

        :returns: 解密验签成功后，返回服务端的消息原文
        """
        if encryptedRespData and isinstance(encryptedRespData, dict):
            JsonAESEncryptedData = encryptedRespData["data"]
            respData = json.loads(AESDecrypt(AESKey, JsonAESEncryptedData))
            metaData = respData.pop("__meta__")
            SignData = self.sign(respData)
            if metaData["Signature"] == SignData:
                return respData


class EncryptedCommunicationServer(EncryptedCommunicationMix):
    """服务端：主要是私钥解密"""

    def serverDecrypt(self, privkey, encryptedPostData):
        """服务端获取请求数据并解密 for NO.2

        :param pubkey: str: RSA的pkcs1或pkcs8格式公钥

        :param postData: dict: 请求的数据

        :returns: tuple: 解密后的请求数据原文和AESKey(用以在返回数据时加密)
        """
        if privkey and encryptedPostData and isinstance(encryptedPostData, dict):
            RSAKey = encryptedPostData["key"]
            print("RSAKey: %s" %RSAKey)
            AESKey = RSADecrypt(privkey, RSAKey)
            print("AESKey: %s" %AESKey)
            JsonAESEncryptedData = encryptedPostData["value"]
            print(JsonAESEncryptedData)
            postData = json.loads(AESDecrypt(AESKey, JsonAESEncryptedData))
            print("postdata: %s" %postData)
            metaData = postData.pop("__meta__")
            SignData = self.sign(postData)
            print("SignData: %s" %SignData)
            if metaData["Signature"] == SignData:
                return postData, AESKey

    def serverEncrypt(self, AESKey, resp):
        """服务端返回加密数据 for NO.3

        :param AESKey: str: 服务端解密时返回的AESKey，即客户端加密时自主生成的AES密钥

        :param resp: dict: 服务端返回的数据，目前仅支持dict

        :returns: dict: 返回dict，格式是 {data: AES加密数据}
        """
        if AESKey and resp and isinstance(resp, dict):
            respData = copy.deepcopy(resp)
            SignData = self.sign(respData)
            respData.update(__meta__=dict(Signature=SignData, Timestamp=self.get_current_timestamp()))
            JsonAESEncryptedData = AESEncrypt(AESKey, json.dumps(respData))
            return dict(data=JsonAESEncryptedData)
