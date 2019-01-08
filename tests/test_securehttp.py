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

        post = {u'a': 1, u'c': 3, u'b': 2, u'data': ["a", 1, None]}
        resp = {u'msg': None, u'code': 0}

        client = EncryptedCommunicationClient(pubkey)
        server = EncryptedCommunicationServer(privkey)

        # NO.1
        c1 = client.clientEncrypt(post)
        if self.debug:
            print("\nNO.1 客户端加密数据：%s" % c1)
        # NO.2
        s1 = server.serverDecrypt(c1)
        self.assertEqual(client.AESKey, server.AESKey)
        if self.debug:
            print("\nNO.2 服务端解密数据：%s" % s1)
        self.assertEqual(s1, post)
        # NO.3
        s2 = server.serverEncrypt(resp, False)
        if self.debug:
            print("\nNO.3 服务端返回加密数据：%s" % s2)
        # NO.4
        c2 = client.clientDecrypt(s2)
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
        ec = EncryptedCommunicationClient(pubkey)
        encryptedPost = ec.clientEncrypt(post)
        resp = self.api2dict(self.client.post('/', data=encryptedPost, follow_redirects=True).data)
        resp = ec.clientDecrypt(resp)
        if self.debug:
            print("\n返回数据解密：%s" %resp)
        self.assertIsInstance(resp, dict)
        self.assertEqual(resp, post)

    def test_complicatedEC1(self):
        post = dict(debug=self.debug)
        ec = EncryptedCommunicationClient(pubkey)
        self.assertEqual(ec.sign(post, dict(SignatureIndex=False)), None)

    def test_complicatedEC2(self):
        post = {"configGlossary:installationAt":"Philadelphia, PA","configGlossary:adminEmail":"ksm@pobox.com","configGlossary:poweredBy":"Cofax","configGlossary:poweredByIcon":"/images/cofax.gif","configGlossary:staticPath":"/content/static","templateProcessorClass":"org.cofax.WysiwygTemplate","templateLoaderClass":"org.cofax.FilesTemplateLoader","templatePath":"templates","templateOverridePath":"","defaultListTemplate":"listTemplate.htm","defaultFileTemplate":"articleTemplate.htm","useJSP":False,"jspListTemplate":"listTemplate.jsp","jspFileTemplate":"articleTemplate.jsp","cachePackageTagsTrack":200,"cachePackageTagsStore":200,"cachePackageTagsRefresh":60,"cacheTemplatesTrack":100,"cacheTemplatesStore":50,"cacheTemplatesRefresh":15,"cachePagesTrack":200,"cachePagesStore":100,"cachePagesRefresh":10,"cachePagesDirtyRead":10,"searchEngineListTemplate":"forSearchEnginesList.htm","searchEngineFileTemplate":"forSearchEngines.htm","searchEngineRobotsDb":"WEB-INF/robots.db","useDataStore":True,"dataStoreClass":"org.cofax.SqlDataStore","redirectionClass":"org.cofax.SqlRedirection","dataStoreName":"cofax","dataStoreDriver":"com.microsoft.jdbc.sqlserver.SQLServerDriver","dataStoreUrl":"jdbc:microsoft:sqlserver://LOCALHOST:1433;DatabaseName=goon","dataStoreUser":"sa","dataStorePassword":"dataStoreTestQuery","dataStoreLogFile":"/usr/local/tomcat/logs/datastore.log","dataStoreInitConns":10,"dataStoreMaxConns":100,"dataStoreConnUsageLimit":100,"dataStoreLogLevel":"debug","maxUrlLength":500,"test-content":None,"test_content2": [1,2,dict(c=3)], "test_content3": 0, "test_content4": dict()}
        resp = {u'msg': None, u'code': 0}

        client = EncryptedCommunicationClient(pubkey)
        server = EncryptedCommunicationServer(privkey)
        s1 = server.serverDecrypt(client.clientEncrypt(post, "configGlossary:installationAt,configGlossary:adminEmail,templateOverridePath,useJSP,cacheTemplatesRefresh,test-content,test_content2,test_content3,test_content4"))
        c2 = client.clientDecrypt(server.serverEncrypt(resp))
        self.assertEqual(client.AESKey, server.AESKey)
        self.assertEqual(s1, post)
        self.assertEqual(c2, resp)

    def test_complicatedEC3(self):
        post = {'test_content': None,  'test_content2': ['a', 'b', 'c'], 'test_content3': 0, 'test_content4': {}, 'test_content5': [1, 2, 3]}
        resp = {u'msg': None, u'code': 0}

        client = EncryptedCommunicationClient(pubkey)
        server = EncryptedCommunicationServer(privkey)
        s1 = server.serverDecrypt(client.clientEncrypt(post))
        c2 = client.clientDecrypt(server.serverEncrypt(resp))
        self.assertEqual(client.AESKey, server.AESKey)
        self.assertEqual(s1, post)
        self.assertEqual(c2, resp)

if __name__ == '__main__':
    unittest.main()
