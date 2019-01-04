# -*- coding: utf-8 -*-
#
# pip install rsa
# 

import rsa
import base64

"""
# 先生成一对密钥，然后生成pkcs1格式内容，可以保存为`.pem`文件，当然也可以直接使用
(pubkey, privkey) = rsa.newkeys(1024)
pubkeyContent = pubkey.save_pkcs1()
prikeyContent = privkey.save_pkcs1()
"""

# pkcs1格式私钥
prikeyContent = '''-----BEGIN RSA PRIVATE KEY-----
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

# pkcs1或pkcs8格式公钥
pubkeyContent = '''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDK7sG7nZnIUAfl6Hf7UwYwdPKu
UjslnB3xAWLZvL295i1e2+tDjN7Eli5yIbhxePxAE760tEAz+6UcWPRGDdlshNRo
Gp4lWob1qMEg/7g8rxvhHioUFjnNE0kRy2OJJ9OQSViUagXs09qeqvs0AssOiGup
S3CJ/G1Dy8TxcHHbwwIDAQAB
-----END PUBLIC KEY-----'''

message = 'Message'
print("will encrypt: %s" %message)

# load公钥和密钥
if pubkeyContent and pubkeyContent.startswith("-----BEGIN RSA PUBLIC KEY-----"):
    pubkey = rsa.PublicKey.load_pkcs1(pubkeyContent) 
else:
    #load_pkcs1_openssl_pem可以加载openssl生成的pkcs1公钥(实为pkcs8格式)
    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(pubkeyContent) 
privkey = rsa.PrivateKey.load_pkcs1(prikeyContent)

# 用公钥加密、再用私钥解密
crypto = rsa.encrypt(message, pubkey)
print(base64.b64encode(crypto))
message = rsa.decrypt(crypto, privkey)
print(message)


# sign 用私钥签名认证、再用公钥验证签名
#signature = rsa.sign(message, privkey, 'SHA-256')
#signOK=rsa.verify(message, signature, pubkey)
#print(signOK)

