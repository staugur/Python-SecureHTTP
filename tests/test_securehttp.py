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
        self.debug = False
        self.client = app.test_client()

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

    def test_ec(self):

        post = {u'a': 1, u'c': 3, u'b': 2}
        resp = {u'msg': None, u'code': 0}

        client = EncryptedCommunicationClient()
        server = EncryptedCommunicationServer()
        AESKey = client.genAesKey()
        # NO.1
        c1 = client.clientEncrypt(AESKey, pubkey, post)
        if self.debug:
            print("\nNO.1 客户端加密数据：%s" % c1)
        # NO.2
        (s1, AESKey2) = server.serverDecrypt(privkey, c1)
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


if __name__ == '__main__':
    unittest.main()
