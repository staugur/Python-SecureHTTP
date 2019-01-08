# -*- coding: utf-8 -*-
import requests
from SecureHTTP import EncryptedCommunicationClient

pubkey = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0nKhCfYfMYxCWI0/gMiiTxJbH
p73Bwff3twyh5/ygLIuSHv7UmRnljiPVG9W/OiOx9NXGldNTbSZexq3FU/PWTtPq
rtwmktCTAl2kpPzYEwyQgtAOHZ4MXuuuRarXYxfcZLm4par4E5bgTzx9DTm9Egc0
1uWkwg3L5bYHMlUE9wIDAQAB
-----END PUBLIC KEY-----"""

post = {"debug": True, "test": True}
ec = EncryptedCommunicationClient(pubkey)
encryptedPost = ec.clientEncrypt(post)
resp = requests.post("http://127.0.0.1:5000", data=encryptedPost).json()
resp = ec.clientDecrypt(resp)
print("\n服务端返回数据：%s" %resp)