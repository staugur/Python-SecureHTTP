# Python-SecureHTTP

通过使用RSA+AES让HTTP传输更加安全，即C/S架构的加密通信!(Make HTTP transmissions more secure via RSA+AES, encrypted communication for C/S architecture.)

[![Build Status](https://travis-ci.com/staugur/Python-SecureHTTP.svg?branch=master)](https://travis-ci.com/staugur/Python-SecureHTTP) [![Documentation Status](https://readthedocs.org/projects/python-securehttp/badge/?version=latest)](https://python-securehttp.readthedocs.io/zh_CN/latest/?badge=latest) [![codecov](https://codecov.io/gh/staugur/Python-SecureHTTP/branch/master/graph/badge.svg)](https://codecov.io/gh/staugur/Python-SecureHTTP) [![PyPI](https://img.shields.io/pypi/v/SecureHTTP.svg?style=popout)](https://pypi.org/project/SecureHTTP) [![Pyversions](https://img.shields.io/pypi/pyversions/SecureHTTP.svg
)](https://pypi.org/project/SecureHTTP) [![Implementation](https://img.shields.io/pypi/implementation/SecureHTTP.svg)](https://pypi.org/project/SecureHTTP)


### 使用概述(Overview)

**安装(Installation)：**

```bash
# 正式版(Release)
$ pip install -U SecureHTTP
# 开发版(Dev)
$ pip install -U git+https://github.com/staugur/Python-SecureHTTP.git
```

**测试用例(TestCase)：**

```bash
$ git clone https://github.com/staugur/Python-SecureHTTP && cd Python-SecureHTTP
$ make test
```

**示例代码(Examples)：**

1. AES加密、解密
```python
from SecureHTTP import AESEncrypt, AESDecrypt
# 加密后的密文
ciphertext = AESEncrypt('ThisIsASecretKey', 'Hello World!')
# 解密后的明文
plaintext = AESDecrypt("ThisIsASecretKey", ciphertext)
```

2. RSA加密、解密
```python
from SecureHTTP import RSAEncrypt, RSADecrypt, generate_rsa_keys
# 生成密钥对
(pubkey, privkey) = generate_rsa_keys(incall=True)
# 加密后的密文
ciphertext = RSAEncrypt(pubkey, 'Hello World!')
# 解密后的明文
plaintext = RSADecrypt(privkey, ciphertext)
```

3. C/S加解密示例：[点此查看以下模拟代码的真实WEB环境示例](https://github.com/staugur/Python-SecureHTTP/blob/master/examples/Demo/)
```python
# 模拟C/S请求
from SecureHTTP import EncryptedCommunicationClient, EncryptedCommunicationServer, generate_rsa_keys
post = {u'a': 1, u'c': 3, u'b': 2, u'data': ["a", 1, None]}
resp = {u'msg': None, u'code': 0}
# 生成密钥对
(pubkey, privkey) = generate_rsa_keys(incall=True)
# 初始化客户端类
client = EncryptedCommunicationClient(pubkey)
# 初始化服务端类
server = EncryptedCommunicationServer(privkey)
# NO.1 客户端加密数据
c1 = client.clientEncrypt(post)
# NO.2 服务端解密数据
s1 = server.serverDecrypt(c1)
# NO.3 服务端返回加密数据
s2 = server.serverEncrypt(resp)
# NO.4 客户端获取返回数据并解密
c2 = client.clientDecrypt(s2)
# 以上四个步骤即完成一次请求/响应
```

4. B/S加解密示例：[前端使用AES+RSA加密，后端解密](https://github.com/staugur/Python-SecureHTTP/tree/master/examples/BS-RSA)


### 文档(Documentation)

* [中文](https://python-securehttp.readthedocs.io/zh_CN/latest/)


### 资源(Resources)

* GitHub [https://github.com/staugur/Python-SecureHTTP](https://github.com/staugur/Python-SecureHTTP "https://github.com/staugur/Python-SecureHTTP")
* Author [https://www.saintic.com](https://www.saintic.com "https://www.saintic.com")
* Issues [https://github.com/staugur/Python-SecureHTTP/issues](https://github.com/staugur/Python-SecureHTTP/issues "https://github.com/staugur/Python-SecureHTTP/issues")


### 说在后面(END)

欢迎提交PR、共同开发！

