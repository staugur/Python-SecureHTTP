# -*- coding: utf-8 -*-
import requests
from SecureHTTP import EncryptedCommunicationClient

pubkey = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0nKhCfYfMYxCWI0/gMiiTxJbH
p73Bwff3twyh5/ygLIuSHv7UmRnljiPVG9W/OiOx9NXGldNTbSZexq3FU/PWTtPq
rtwmktCTAl2kpPzYEwyQgtAOHZ4MXuuuRarXYxfcZLm4par4E5bgTzx9DTm9Egc0
1uWkwg3L5bYHMlUE9wIDAQAB
-----END PUBLIC KEY-----"""

post = dict(debug=True)
ec = EncryptedCommunicationClient()
AESKey = ec.genAesKey()
encryptedPost = ec.clientEncrypt(AESKey, pubkey, post)
resp = requests.post("http://127.0.0.1:5000", data=encryptedPost).json()
resp = ec.clientDecrypt(AESKey, resp)
print("\n返回数据解密：%s" %resp)