# -*- coding: utf-8 -*-

import os
import json
import base64
import unittest
from webapp import app, privkey, pubkey
from SecureHTTP import RSAEncrypt, RSADecrypt, AESEncrypt, AESDecrypt, EncryptedCommunicationClient, EncryptedCommunicationServer, PY2, generate_rsa_keys, required_string, AESError
from binascii import b2a_hex, a2b_hex


class UtilsTest(unittest.TestCase):

    def setUp(self):
        self.debug = False
        self.client = app.test_client()

    def test_require_string(self):
        self.assertRaises(TypeError, required_string, [])
        self.assertRaises(TypeError, required_string, {})
        if PY2:
            t1 = "abc"
            self.assertIsInstance(required_string(t1), unicode)
            self.assertIsInstance(required_string(t1, "str"), str)
            self.assertRaises(ValueError, required_string, t1, "other")
            self.assertEqual(t1, required_string(t1))
            t2 = u"def"
            self.assertIsInstance(required_string(t2), unicode)
            self.assertIsInstance(required_string(t2, "str"), str)
            self.assertEqual(t2, required_string(t2))
            t3 = '你好'
            self.assertIsInstance(required_string(t3), unicode)
            self.assertIsInstance(required_string(t3, "str"), str)
            self.assertEqual(t3.decode("utf-8"), required_string(t3))
            t4 = u'你好'
            self.assertIsInstance(required_string(t4), unicode)
            self.assertIsInstance(required_string(t4, "str"), str)
            self.assertEqual(t4, required_string(t4))
            self.assertEqual(t4.encode("utf-8"), required_string(t4, "str"))
        else:
            t1 = "abc"
            self.assertIsInstance(required_string(t1), bytes)
            self.assertIsInstance(required_string(t1, "str"), str)
            self.assertRaises(ValueError, required_string, t1, "unicode")
            self.assertEqual(t1.encode("utf-8"), required_string(t1))
            self.assertEqual(t1, required_string(t1, "str"))
            t2 = b"def"
            self.assertIsInstance(required_string(t2), bytes)
            self.assertIsInstance(required_string(t2, "str"), str)
            self.assertEqual(t2, required_string(t2))
            self.assertEqual(t2.decode("utf-8"), required_string(t2, "str"))
            t3 = '你好'
            self.assertIsInstance(required_string(t3), bytes)
            self.assertIsInstance(required_string(t3, "str"), str)
            self.assertEqual(t3, required_string(t3, "str"))
            self.assertEqual(t3.encode("utf-8"), required_string(t3))
            t4 = '你好'.encode("utf-8")
            self.assertIsInstance(required_string(t4), bytes)
            self.assertIsInstance(required_string(t4, "str"), str)
            self.assertEqual(t4, required_string(t4))
            self.assertEqual(t4.decode("utf-8"), required_string(t4, "str"))

    def test_AES(self):
        key = "secretsecretsecr"
        to_encrypt = 'Message'
        to_decrypt = 'AJ1W95LMUWjuXzHP2lqFlA=='
        to_decrypt_16 = '009d56f792cc5168ee5f31cfda5a8594'
        # 测试base64与十六进制互相转换
        self.assertEqual(to_decrypt, base64.b64encode(a2b_hex(to_decrypt_16)).decode("utf-8"))
        self.assertEqual(b2a_hex(base64.b64decode(to_decrypt)).decode("utf-8"), to_decrypt_16)
        # 测试加密
        self.assertEqual(to_decrypt.encode("utf-8"), AESEncrypt(key, to_encrypt))
        self.assertEqual(b2a_hex(base64.b64decode(to_decrypt)).decode("utf-8"), to_decrypt_16)
        # 测试解密
        self.assertEqual(to_encrypt, AESDecrypt(key, to_decrypt, output_type="str"))
        self.assertEqual(to_encrypt.encode("utf-8"), AESDecrypt(key, to_decrypt))
        self.assertEqual(to_encrypt.encode("utf-8"), AESDecrypt(key, base64.b64encode(a2b_hex(to_decrypt_16)).decode("utf-8")))
        # 测试中文
        self.assertRaises(AESError, AESEncrypt, '你好key','message')
        k='x'*24
        pt='你好'
        self.assertEqual(pt, AESDecrypt(k, AESEncrypt(k, pt), output_type="str"))

    def test_generate_rsa_keys(self):
        (pub, pri) = generate_rsa_keys(incall=True)
        text = b"helloWorld"
        self.assertEqual(RSADecrypt(pri, RSAEncrypt(pub, text)), text)

    def test_generate_rsa_keys_with_pass(self):
        passphrase = b"abcde"
        (pub, pri) = generate_rsa_keys(incall=True, length=1024, passphrase=passphrase)
        text = b"Hello World!"
        self.assertEqual(RSADecrypt(pri, RSAEncrypt(pub, text), passphrase=passphrase), text)

    def test_RSA(self):
        plaintext = b"Message"
        ciphertext = RSAEncrypt(pubkey, plaintext)
        to_decrypt = RSADecrypt(privkey, ciphertext)
        self.assertEqual(plaintext, to_decrypt)


    def test_pkcs1(self):
        privkey = '''-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDBVAczL3sjEVewm0+XWo/g1QbqM9veVKmETH37CqJrTB/TEg9t
/HyRtPCUCnx6sj0xyQPTBRrKZn4D69zqNiRwBOPza6E8QhmUPTtRam4nFbUMj7n7
97gcrUpT2GSdA94Ags3xB0ucCHi/nWEZyfUxGZjb6L3+3NgPoCQknwoV8wIDAQAB
AoGAZ/g1qwxU76YK/7p20lHs4KAQCPH8w5PKWpD8i37LnGKjFtM2oxLPN1kUrLj6
+s1SZazSNrEfGEyIZrl45Chb7UcZu2B8ZNve7LpZAPrhkGXv48OJioTsVGYpBEYG
viTcrBKHfNT9XfkDwSNR9y4mPDf92vpUYboNox9IcFESzPECQQDf9PDsDnd7zgzZ
CGDCnWeVqS/+nEZtZckTlrzsajj/9UmvnvUgHS/o6eQZQPTroB74FMujLL9HShNI
F75Mm+7LAkEA3P06ZW009rqvKf3g1E6sHEQvOp7rCD3grLbVSQ8Y9wogYDTZqON8
VvrmawIBHfMkdlLCcU/+QsrWajIZkMOoeQJAHHSb0/J2ngVtPnpBCRlE2xA3J+ul
SysepF2HvaY1fdglt6nDzYPH3ZkyQT8un22l4bGKuj3qQ92Wm5dgt40shwJBALJT
sgzo3EWBjhovoX8RYTeKGiaO2RCUhjo5a9GB2l53kHqyCzaLI+o4mzmcq3QUocbN
r9SqfX4+mlmlxhWYndkCQQCuA/8YrkMrQIZWlErBRldtV1gqoToyexsJjxAuLP0d
XM5dHfZ/oq/dqXCUN/iMRG1qxaA7qT4kYb+n6Nb3JYxG
-----END RSA PRIVATE KEY-----'''
        pubkey = '''-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMFUBzMveyMRV7CbT5daj+DVBuoz295UqYRMffsKomtMH9MSD238fJG0
8JQKfHqyPTHJA9MFGspmfgPr3Oo2JHAE4/NroTxCGZQ9O1FqbicVtQyPufv3uByt
SlPYZJ0D3gCCzfEHS5wIeL+dYRnJ9TEZmNvovf7c2A+gJCSfChXzAgMBAAE=
-----END RSA PUBLIC KEY-----'''
        self.assertEqual(b'test', RSADecrypt(privkey, RSAEncrypt(pubkey, 'test')))
        self.assertEqual(b'test', RSADecrypt(privkey.encode("utf-8"), RSAEncrypt(pubkey.encode("utf-8"), 'test')))

    def test_pkcs8(self):
        privkey = '''-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDBVAczL3sjEVewm0+XWo/g1QbqM9veVKmETH37CqJrTB/TEg9t
/HyRtPCUCnx6sj0xyQPTBRrKZn4D69zqNiRwBOPza6E8QhmUPTtRam4nFbUMj7n7
97gcrUpT2GSdA94Ags3xB0ucCHi/nWEZyfUxGZjb6L3+3NgPoCQknwoV8wIDAQAB
AoGAZ/g1qwxU76YK/7p20lHs4KAQCPH8w5PKWpD8i37LnGKjFtM2oxLPN1kUrLj6
+s1SZazSNrEfGEyIZrl45Chb7UcZu2B8ZNve7LpZAPrhkGXv48OJioTsVGYpBEYG
viTcrBKHfNT9XfkDwSNR9y4mPDf92vpUYboNox9IcFESzPECQQDf9PDsDnd7zgzZ
CGDCnWeVqS/+nEZtZckTlrzsajj/9UmvnvUgHS/o6eQZQPTroB74FMujLL9HShNI
F75Mm+7LAkEA3P06ZW009rqvKf3g1E6sHEQvOp7rCD3grLbVSQ8Y9wogYDTZqON8
VvrmawIBHfMkdlLCcU/+QsrWajIZkMOoeQJAHHSb0/J2ngVtPnpBCRlE2xA3J+ul
SysepF2HvaY1fdglt6nDzYPH3ZkyQT8un22l4bGKuj3qQ92Wm5dgt40shwJBALJT
sgzo3EWBjhovoX8RYTeKGiaO2RCUhjo5a9GB2l53kHqyCzaLI+o4mzmcq3QUocbN
r9SqfX4+mlmlxhWYndkCQQCuA/8YrkMrQIZWlErBRldtV1gqoToyexsJjxAuLP0d
XM5dHfZ/oq/dqXCUN/iMRG1qxaA7qT4kYb+n6Nb3JYxG
-----END RSA PRIVATE KEY-----'''
        pubkey = '''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBVAczL3sjEVewm0+XWo/g1Qbq
M9veVKmETH37CqJrTB/TEg9t/HyRtPCUCnx6sj0xyQPTBRrKZn4D69zqNiRwBOPz
a6E8QhmUPTtRam4nFbUMj7n797gcrUpT2GSdA94Ags3xB0ucCHi/nWEZyfUxGZjb
6L3+3NgPoCQknwoV8wIDAQAB
-----END PUBLIC KEY-----'''
        self.assertEqual(b'test', RSADecrypt(privkey, RSAEncrypt(pubkey, 'test')))
        self.assertEqual(b'test', RSADecrypt(privkey.encode("utf-8"), RSAEncrypt(pubkey.encode("utf-8"), 'test')))

    def test_ec(self):

        post = {u'a': 1, u'c': 3, u'b': 2, u'data': ["a", 1, None]}
        resp = {u'msg': None, u'code': 0}

        client = EncryptedCommunicationClient(pubkey)
        server = EncryptedCommunicationServer(privkey)

        self.assertRaises(TypeError, client.sign, 'raise')
        self.assertRaises(TypeError, client.clientEncrypt, 'raise')
        self.assertRaises(TypeError, client.clientDecrypt, 'raise')
        self.assertRaises(TypeError, server.serverDecrypt, 'raise')
        self.assertRaises(ValueError, server.serverEncrypt, 'raise')
        self.assertEqual(len(client.AESKey), 16)
        # test aam
        self.assertEqual(client.abstract_algorithm_mapping("sha1")("123"), client.sha1("123"))

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
        s2 = server.serverEncrypt(resp, signIndex=False)
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
            print("\n返回数据解密：%s" % resp)
        self.assertIsInstance(resp, dict)
        self.assertEqual(resp, post)

    def test_complicatedEC1(self):
        post = dict(debug=self.debug)
        ec = EncryptedCommunicationClient(pubkey)
        self.assertEqual(ec.sign(post, dict(SignatureIndex=False)), None)

    def test_complicatedEC2(self):
        post = {"configGlossary:installationAt": "Philadelphia, PA", "configGlossary:adminEmail": "ksm@pobox.com", "configGlossary:poweredBy": "Cofax", "configGlossary:poweredByIcon": "/images/cofax.gif", "configGlossary:staticPath": "/content/static", "templateProcessorClass": "org.cofax.WysiwygTemplate", "templateLoaderClass": "org.cofax.FilesTemplateLoader", "templatePath": "templates", "templateOverridePath": "", "defaultListTemplate": "listTemplate.htm", "defaultFileTemplate": "articleTemplate.htm", "useJSP": False, "jspListTemplate": "listTemplate.jsp", "jspFileTemplate": "articleTemplate.jsp", "cachePackageTagsTrack": 200, "cachePackageTagsStore": 200, "cachePackageTagsRefresh": 60, "cacheTemplatesTrack": 100, "cacheTemplatesStore": 50, "cacheTemplatesRefresh": 15, "cachePagesTrack": 200, "cachePagesStore": 100, "cachePagesRefresh": 10, "cachePagesDirtyRead": 10, "searchEngineListTemplate": "forSearchEnginesList.htm", "searchEngineFileTemplate": "forSearchEngines.htm", "searchEngineRobotsDb": "WEB-INF/robots.db", "useDataStore": True, "dataStoreClass": "org.cofax.SqlDataStore", "redirectionClass": "org.cofax.SqlRedirection", "dataStoreName": "cofax", "dataStoreDriver": "com.microsoft.jdbc.sqlserver.SQLServerDriver", "dataStoreUrl": "jdbc:microsoft:sqlserver://LOCALHOST:1433;DatabaseName=goon", "dataStoreUser": "sa", "dataStorePassword": "dataStoreTestQuery", "dataStoreLogFile": "/usr/local/tomcat/logs/datastore.log", "dataStoreInitConns": 10, "dataStoreMaxConns": 100, "dataStoreConnUsageLimit": 100, "dataStoreLogLevel": "debug", "maxUrlLength": 500, "test-content": None, "test_content2": [1, 2, dict(c=3)], "test_content3": 0, "test_content4": dict()}
        resp = {u'msg': None, u'code': 0}

        client = EncryptedCommunicationClient(pubkey)
        server = EncryptedCommunicationServer(privkey)
        s1 = server.serverDecrypt(client.clientEncrypt(post, signMethod="sha1", signIndex="configGlossary:installationAt,configGlossary:adminEmail,templateOverridePath,useJSP,cacheTemplatesRefresh,test-content,test_content2,test_content3,test_content4"))
        c2 = client.clientDecrypt(server.serverEncrypt(resp))
        self.assertEqual(client.AESKey, server.AESKey)
        self.assertEqual(s1, post)
        self.assertEqual(c2, resp)

    def test_complicatedEC3(self):
        post = {'t1': None,  't2': ['a', 'c'], 't3': 0, 't4': 't4', 't5': dict(a=[1,], c=None, b=dict(b1=1))}
        resp = {u'msg': None, u'code': 0}

        client = EncryptedCommunicationClient(pubkey)
        server = EncryptedCommunicationServer(privkey)
        s1 = server.serverDecrypt(client.clientEncrypt(post, signMethod="sha256"))
        c2 = client.clientDecrypt(server.serverEncrypt(resp))
        self.assertEqual(client.AESKey, server.AESKey)
        self.assertEqual(s1, post)
        self.assertEqual(c2, resp)

    def test_complicatedEC4(self):
        resp = {u'msg': None, u'code': 0}
        post = {u'web-app': {u'servlet-mapping': {u'cofaxCDS': u'/', u'cofaxAdmin': u'/admin/*', u'fileServlet': u'/static/*', u'cofaxTools': u'/tools/*', u'cofaxEmail': u'/cofaxutil/aemail/*'}, u'taglib': {u'taglib-location': u'/WEB-INF/tlds/cofax.tld', u'taglib-uri': u'cofax.tld'}, u'servlet': [{u'servlet-name': u'cofaxCDS', u'init-param': {u'cachePagesStore': 100, u'searchEngineListTemplate': u'forSearchEnginesList.htm', u'templateLoaderClass': u'org.cofax.FilesTemplateLoader', u'maxUrlLength': 500, u'dataStoreTestQuery': u"SET NOCOUNT ON;select test='test';", u'defaultFileTemplate': u'articleTemplate.htm', u'dataStoreLogFile': u'/usr/local/tomcat/logs/datastore.log', u'configGlossary:adminEmail': u'ksm@pobox.com', u'dataStoreClass': u'org.cofax.SqlDataStore', u'configGlossary:installationAt': u'Philadelphia, PA', u'configGlossary:poweredBy': u'Cofax', u'cacheTemplatesStore': 50, u'dataStoreUrl': u'jdbc:microsoft:sqlserver://LOCALHOST:1433;DatabaseName=goon', u'dataStoreDriver': u'com.microsoft.jdbc.sqlserver.SQLServerDriver', u'cachePagesTrack': 200, u'cachePackageTagsStore': 200, u'dataStoreName': u'cofax', u'dataStorePassword': u'dataStoreTestQuery', u'useJSP': False, u'defaultListTemplate': u'listTemplate.htm', u'templateOverridePath': u'', u'dataStoreUser': u'sa', u'jspListTemplate': u'listTemplate.jsp', u'jspFileTemplate': u'articleTemplate.jsp', u'dataStoreMaxConns': 100, u'cachePagesDirtyRead': 10, u'cachePagesRefresh': 10, u'cacheTemplatesTrack': 100, u'dataStoreConnUsageLimit': 100, u'redirectionClass': u'org.cofax.SqlRedirection', u'searchEngineRobotsDb': u'WEB-INF/robots.db', u'templateProcessorClass': u'org.cofax.WysiwygTemplate', u'cachePackageTagsRefresh': 60, u'configGlossary:staticPath': u'/content/static', u'templatePath': u'templates', u'useDataStore': True, u'cacheTemplatesRefresh': 15, u'searchEngineFileTemplate': u'forSearchEngines.htm', u'configGlossary:poweredByIcon': u'/images/cofax.gif', u'cachePackageTagsTrack': 200, u'dataStoreLogLevel': u'debug', u'dataStoreInitConns': 10}, u'servlet-class': u'org.cofax.cds.CDSServlet'}, {u'servlet-name': u'cofaxEmail', u'init-param': {u'mailHostOverride': u'mail2', u'mailHost': u'mail1'}, u'servlet-class': u'org.cofax.cds.EmailServlet'}, {u'servlet-name': u'cofaxAdmin', u'servlet-class': u'org.cofax.cds.AdminServlet'}, {u'servlet-name': u'fileServlet', u'servlet-class': u'org.cofax.cds.FileServlet'}, {u'servlet-name': u'cofaxTools', u'init-param': {u'logLocation': u'/usr/local/tomcat/logs/CofaxTools.log', u'fileTransferFolder': u'/usr/local/tomcat/webapps/content/fileTransferFolder', u'log': 1, u'dataLog': 1, u'dataLogLocation': u'/usr/local/tomcat/logs/dataLog.log', u'adminGroupID': 4, u'lookInContext': 1, u'removeTemplateCache': u'/content/admin/remove?cache=templates&id=', u'logMaxSize': u'', u'dataLogMaxSize': u'', u'removePageCache': u'/content/admin/remove?cache=pages&id=', u'betaServer': True, u'templatePath': u'toolstemplates/'}, u'servlet-class': u'org.cofax.cms.CofaxToolsServlet'}]}}

        client = EncryptedCommunicationClient(pubkey)
        server = EncryptedCommunicationServer(privkey)
        s1 = server.serverDecrypt(client.clientEncrypt(post))
        c2 = client.clientDecrypt(server.serverEncrypt(resp))
        self.assertEqual(client.AESKey, server.AESKey)
        self.assertEqual(s1, post)
        self.assertEqual(c2, resp)

if __name__ == '__main__':
    unittest.main()
