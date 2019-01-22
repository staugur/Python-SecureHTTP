# -*- coding: utf-8 -*-
import os
import base64
import unittest
from SecureHTTP import RSAEncrypt, RSADecrypt, AESEncrypt, AESDecrypt
from binascii import b2a_hex, a2b_hex

privkey = '''-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDK7sG7nZnIUAfl6Hf7UwYwdPKuUjslnB3xAWLZvL295i1e2+tD
jN7Eli5yIbhxePxAE760tEAz+6UcWPRGDdlshNRoGp4lWob1qMEg/7g8rxvhHioU
FjnNE0kRy2OJJ9OQSViUagXs09qeqvs0AssOiGupS3CJ/G1Dy8TxcHHbwwIDAQAB
AoGBAI0THitHjLjsqhDyYzacqRjWtD7re6LRvR7mT8n+pAl4EuJ3ED6Nl/AiV3eQ
aaC48uO41kLZbCi3MDlcvbRVvGetyPkzK51uSFcQauwq6p/S/Tz/l9HD5pK1Cl2F
Zjpcq4KkZbFXqL98VJn1klvpta2WiK5g77+EwnDPYM4TptFBAkEA/hR/lVp0DJ2j
jzwrRdnB1peM6I7NsoynNll7BHWhvo+zRCmwwsHUAEVfw/TIoQyRWJJoVg8UUEFL
m3JNU3nFxwJBAMx3USUV7anwqalPCXjUqj0AIENVrpyJ0tyjPx9fixBoUrRQKo6e
53xmDlemWWxYAMgnnzaSOs4wbvDjCk7tiiUCQHk1DigRnormKMCL05je6LmWUoIe
ncIvlxU2WpkmBKMDqmE6AjjmflwivCye+Zbah/vY3C0xxF8ExyzAumK4FMECQBBE
VeJbckMY8IaV0S0Zzkl4Hxj8Uh4GIQ6ItlbqpQezJRFPZ3NdVRFilTWH+IlUHwvN
iy8uRxtsYwcrKQDKiTkCQCJpaFG/PZZV1+a8xsouoGFdRFHfDPPmRoKmRpyBdOab
t/qer6PoUMwhXvE6nMb7FD/Uyj5GMrSKqbNTsVA3gx0=
-----END RSA PRIVATE KEY-----'''
pubkey = '''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDK7sG7nZnIUAfl6Hf7UwYwdPKu
UjslnB3xAWLZvL295i1e2+tDjN7Eli5yIbhxePxAE760tEAz+6UcWPRGDdlshNRo
Gp4lWob1qMEg/7g8rxvhHioUFjnNE0kRy2OJJ9OQSViUagXs09qeqvs0AssOiGup
S3CJ/G1Dy8TxcHHbwwIDAQAB
-----END PUBLIC KEY-----'''

class MultiLanguagesTest(unittest.TestCase):

    def setUp(self):
        self.examplespath = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples")

    def test_AES(self):
        key = "secretsecretsecr"
        to_encrypt = 'Message'
        to_decrypt_16 = '009d56f792cc5168ee5f31cfda5a8594'

        # 执行go程序获取打印结果并解析对比
        godata = os.popen('go run %s/AES-CBC-PKCS5Padding/acp.go' %self.examplespath).read()
        godata = dict([ i.split(': ') for i in godata.split('\n') if i ])
        self.assertEqual(godata["plain"], godata["newPlain"])
        self.assertEqual(godata["newPlain"], to_encrypt)
        self.assertEqual(godata["cipher"], to_decrypt_16)

        # 执行php程序
        phpdata = os.popen('php %s/AES-CBC-PKCS5Padding/acp.php' %self.examplespath).read().split("\n")
        self.assertEqual(phpdata[0], to_decrypt_16)
        self.assertEqual(phpdata[1], to_encrypt)

        # 执行python程序
        # 测试加密
        pyencrypt16 = b2a_hex(base64.b64decode(AESEncrypt(key, to_encrypt))).decode("utf-8")
        self.assertEqual(pyencrypt16, to_decrypt_16)
        self.assertEqual(pyencrypt16, godata["cipher"])
        self.assertEqual(pyencrypt16, phpdata[0])

        # 测试解密
        pydecryptedSrc = AESDecrypt(key, AESEncrypt(key, to_encrypt))
        self.assertEqual(pydecryptedSrc, to_encrypt)
        self.assertEqual(pydecryptedSrc, phpdata[1])
        self.assertEqual(pydecryptedSrc, godata["newPlain"])

    def test_RSA(self):
        plaintext = "Message"
        ciphertext = RSAEncrypt(pubkey, plaintext)
        self.assertEqual(plaintext, RSADecrypt(privkey, ciphertext))

        # 执行go程序
        godata = os.popen('go run %s/RSA-PKCS1-PEM/rsa-pkcs1.go' %self.examplespath).read()
        godata = dict([ i.split(": ") for i in godata.split("\n") if i ])
        self.assertEqual(godata['rsa decrypted'], plaintext)
        self.assertEqual(RSADecrypt(privkey, godata['rsa encrypt base64']), plaintext)

        # 执行php程序
        phpdata = os.popen('php %s/RSA-PKCS1-PEM/rsa-pkcs1.php' %self.examplespath).read()
        phpdata = phpdata.split("\n")
        phpdata = phpdata[phpdata.index("public key encrypt:"):]
        self.assertEqual(phpdata[3], plaintext)
        self.assertEqual(RSADecrypt(privkey, phpdata[1]), plaintext)

if __name__ == '__main__':
    import unittest
    unittest.main()
