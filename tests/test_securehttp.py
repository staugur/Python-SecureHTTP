# -*- coding: utf-8 -*-

import os
import json
import base64
import unittest
from webapp import app, privkey, pubkey
from SecureHTTP import RSAEncrypt, RSADecrypt, AESEncrypt, AESDecrypt, EncryptedCommunicationClient, EncryptedCommunicationServer, PY2
from binascii import b2a_hex, a2b_hex


class UtilsTest(unittest.TestCase):

    def setUp(self):
        self.debug = True
        self.client = app.test_client()

    """
    def test_AES(self):
        key = "secretsecretsecr"
        to_encrypt = 'Message'
        to_decrypt = 'AJ1W95LMUWjuXzHP2lqFlA=='
        to_decrypt_16 = '009d56f792cc5168ee5f31cfda5a8594'
        # 测试base64与十六进制互相转换
        self.assertEqual(to_decrypt, base64.b64encode(a2b_hex(to_decrypt_16)))
        self.assertEqual(b2a_hex(base64.b64decode(to_decrypt)), to_decrypt_16)
        # 测试加密
        self.assertEqual(to_decrypt, AESEncrypt(key, to_encrypt))
        self.assertEqual(b2a_hex(base64.b64decode(to_decrypt)), to_decrypt_16)
        # 测试解密
        self.assertEqual(to_encrypt, AESDecrypt(key, to_decrypt))
        self.assertEqual(to_encrypt, AESDecrypt(key, base64.b64encode(a2b_hex(to_decrypt_16))))

    def test_RSA(self):
        plaintext = "Message"
        ciphertext = RSAEncrypt(pubkey, plaintext)
        to_decrypt = RSADecrypt(privkey, ciphertext)
        self.assertEqual(plaintext, to_decrypt)
    """

    def test_ec(self):

        #post = {u'a': 1, u'c': 3, u'b': 2}
        resp = {u'msg': None, u'code': 0}
        post = {u'images': [{u'startdate': u'20171009', u'urlbase': u'/az/hprichbg/rb/SoyuzReturn_ZH-CN9848773206', u'enddate': u'20171010', u'copyright': u'\u8054\u76df\u53f7\u822a\u5929\u5668\u4e0b\u964d\u6a21\u5757\u8fd4\u56de\u5730\u7403 (\xa9 Bill Ingalls/NASA)', u'url': u'/az/hprichbg/rb/SoyuzReturn_ZH-CN9848773206_1920x1080.jpg', u'hs': [], u'hsh': u'8c4989f0b54d9f847280af90f0ced6d1', u'bot': 1, u'quiz': u'/search?q=Bing+homepage+quiz&filters=WQOskey:%22HPQuiz_20171009_SoyuzReturn%22&FORM=HPQUIZ', u'drk': 1, u'copyrightlink': u'http://www.bing.com/search?q=%E8%88%AA%E5%A4%A9%E5%99%A8&form=hpcapt&mkt=zh-cn', u'wp': True, u'fullstartdate': u'201710091600', u'top': 1}], u'tooltips': {u'previous': u'\u4e0a\u4e00\u4e2a\u56fe\u50cf', u'walls': u'\u4e0b\u8f7d\u4eca\u65e5\u7f8e\u56fe\u3002\u4ec5\u9650\u7528\u4f5c\u684c\u9762\u58c1\u7eb8\u3002', u'loading': u'\u6b63\u5728\u52a0\u8f7d...', u'walle': u'\u6b64\u56fe\u7247\u4e0d\u80fd\u4e0b\u8f7d\u7528\u4f5c\u58c1\u7eb8\u3002', u'next': u'\u4e0b\u4e00\u4e2a\u56fe\u50cf'}}

        client = EncryptedCommunicationClient()
        server = EncryptedCommunicationServer()
        AESKey = client.genAesKey()
        # NO.1
        c1 = client.clientEncrypt(AESKey, pubkey, post)
        if self.debug:
            print("\nNO.1 客户端加密数据：%s" % c1)
        # NO.2
        (s1, AESKey2) = server.serverDecrypt(privkey, c1)
        print("s1 AESKey2: %s" %AESKey2)
        exit()
        self.assertEqual(AESKey, AESKey2)
        if self.debug:
            print("\nNO.2 服务端解密数据：%s" % s1)
        self.assertEqual(s1, post)
        # NO.3
        s2 = server.serverEncrypt(AESKey, resp)
        if self.debug:
            print("\nNO.3 服务端返回加密数据：%s" % s2)
        # NO.4
        c2 = client.clientDecrypt(AESKey, s2)
        if self.debug:
            print("\nNO.4 客户端获取返回数据并解密：%s" % c2)
        self.assertEqual(c2, resp)

    """
    def api2dict(self, res):
        if PY2:
            return json.loads(res)
        else:
            return json.loads(res.decode('utf-8'))

    def test_web(self):
        post = dict(debug=self.debug)
        ec = EncryptedCommunicationClient()
        AESKey = ec.genAesKey()
        encryptedPost = ec.clientEncrypt(AESKey, pubkey, post)
        resp = self.api2dict(self.client.post('/', data=encryptedPost, follow_redirects=True).data)
        resp = ec.clientDecrypt(AESKey, resp)
        if self.debug:
            print("\n返回数据解密：%s" %resp)
        self.assertIsInstance(resp, dict)
        self.assertEqual(resp, post)
    """

if __name__ == '__main__':
    unittest.main()
