# -*- coding: utf-8 -*-
import requests
from SecureHTTP import EncryptedCommunicationClient

pubkey = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0nKhCfYfMYxCWI0/gMiiTxJbH
p73Bwff3twyh5/ygLIuSHv7UmRnljiPVG9W/OiOx9NXGldNTbSZexq3FU/PWTtPq
rtwmktCTAl2kpPzYEwyQgtAOHZ4MXuuuRarXYxfcZLm4par4E5bgTzx9DTm9Egc0
1uWkwg3L5bYHMlUE9wIDAQAB
-----END PUBLIC KEY-----"""

post = {u'images': [{u'startdate': u'20171009', u'urlbase': u'/az/hprichbg/rb/SoyuzReturn_ZH-CN9848773206', u'enddate': u'20171010', u'copyright': u'\u8054\u76df\u53f7\u822a\u5929\u5668\u4e0b\u964d\u6a21\u5757\u8fd4\u56de\u5730\u7403 (\xa9 Bill Ingalls/NASA)', u'url': u'/az/hprichbg/rb/SoyuzReturn_ZH-CN9848773206_1920x1080.jpg', u'hs': [], u'hsh': u'8c4989f0b54d9f847280af90f0ced6d1', u'bot': 1, u'quiz': u'/search?q=Bing+homepage+quiz&filters=WQOskey:%22HPQuiz_20171009_SoyuzReturn%22&FORM=HPQUIZ', u'drk': 1, u'copyrightlink': u'http://www.bing.com/search?q=%E8%88%AA%E5%A4%A9%E5%99%A8&form=hpcapt&mkt=zh-cn', u'wp': True, u'fullstartdate': u'201710091600', u'top': 1}], u'tooltips': {u'previous': u'\u4e0a\u4e00\u4e2a\u56fe\u50cf', u'walls': u'\u4e0b\u8f7d\u4eca\u65e5\u7f8e\u56fe\u3002\u4ec5\u9650\u7528\u4f5c\u684c\u9762\u58c1\u7eb8\u3002', u'loading': u'\u6b63\u5728\u52a0\u8f7d...', u'walle': u'\u6b64\u56fe\u7247\u4e0d\u80fd\u4e0b\u8f7d\u7528\u4f5c\u58c1\u7eb8\u3002', u'next': u'\u4e0b\u4e00\u4e2a\u56fe\u50cf'}}
#post = {"debug": True}
ec = EncryptedCommunicationClient()
AESKey = ec.genAesKey()
encryptedPost = ec.clientEncrypt(AESKey, pubkey, post)
resp = requests.post("http://127.0.0.1:5000", data=encryptedPost,headers={'Content-Type':'application/json'}).json()
resp = ec.clientDecrypt(AESKey, resp)
print("\n返回数据解密：%s" %resp)