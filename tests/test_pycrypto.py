# -*- coding: utf-8 -*-
import os
os.system("pip uninstall -y pycryptodomex")
if os.getenv("TRAVIS"):
    os.system("pip install pycryptodome")
else:
    os.system("pip install pycrypto")
from test_securehttp import UtilsTest
from SecureHTTP import RSAEncrypt, RSADecrypt


class RSATest(UtilsTest):

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
        self.assertEqual('test', RSADecrypt(privkey, RSAEncrypt(pubkey, 'test')))
        self.assertEqual('test', RSADecrypt(privkey.encode("utf-8"), RSAEncrypt(pubkey.encode("utf-8"), 'test')))

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
        self.assertEqual('test', RSADecrypt(privkey, RSAEncrypt(pubkey, 'test')))
        self.assertEqual('test', RSADecrypt(privkey.encode("utf-8"), RSAEncrypt(pubkey.encode("utf-8"), 'test')))

if __name__ == '__main__':
    import unittest
    unittest.main()


