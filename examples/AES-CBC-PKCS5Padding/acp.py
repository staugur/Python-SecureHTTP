# coding:utf8
"""
本文采用的AES CBC PKCS5padding方式加解密：

1. 密钥和IV相同，可以自己定义IV的值；

2. 这里加解密接收的数据是字符串 字符串 字符串 ，重要的事情说三遍

3. 当前输出的方式HEX方式，可以使用base64（注掉的那部分）

"""
import re
import base64
import binascii
from Crypto.Cipher import AES


class AESCBC:
    def __init__(self):
        self.key = 'secretsecretsecr'  # 定义key值，16位字符串
        self.iv = self.key[:16]  # iv设置为key的前16位，
        self.mode = AES.MODE_CBC
        self.bs = 16  # block size
        self.PADDING = lambda s: s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    def encrypt(self, text):
        generator = AES.new(self.key, self.mode, self.iv)  # 这里的key 和IV 一样 ，可以按照自己的值定义
        crypt = generator.encrypt(self.PADDING(text))
        # crypted_str = base64.b64encode(crypt)   #输出Base64
        crypted_str = binascii.b2a_hex(crypt)  # 输出Hex
        result = crypted_str.decode()
        return result

    def decrypt(self, text):
        generator = AES.new(self.key, self.mode, self.iv)
        text += (len(text) % 4) * '='
        # decrpyt_bytes = base64.b64decode(text)           #输出Base64
        decrpyt_bytes = binascii.a2b_hex(text)  # 输出Hex
        meg = generator.decrypt(decrpyt_bytes)
        # 去除解码后的非法字符
        try:
            result = re.compile('[\\x00-\\x08\\x0b-\\x0c\\x0e-\\x1f\n\r\t]').sub('', meg.decode())
        except Exception:
            result = '解码失败，请重试!'
        return result


if __name__ == '__main__':
    aes = AESCBC()

    to_encrypt = 'Message'
    to_decrypt = '009d56f792cc5168ee5f31cfda5a8594'
    # base64      'AJ1W95LMUWjuXzHP2lqFlA=='

    print("\n加密前:{0}\n加密后：{1}\n".format(to_encrypt, aes.encrypt(to_encrypt)))
    print("解密前:{0}\n解密后：{1}".format(to_decrypt, aes.decrypt(to_decrypt)))
