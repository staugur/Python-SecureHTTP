
V0.5.0
------

Released in 2019-04-25

- fix: 修复AES加密key长度问题 (#2)
- feat: 新增 :func:`required_string` 转化不同py版本的字符串
- feat: 新增AES加密参数，可以定义返回加密的字符串的类型
- feat: 新增RSA加密输出/解密输入的编码参数(hex、base64)
- feat: 更新 :class:`EncryptedCommunicationMix` 中生成AESKey的函数，现在生成的key默认为16字节
- chore: AES加密解密函数调整
- chore: 不再支持pycrypto和pycryptodome，一律使用pycryptodomex！
- chore: Update README.md to README.rst
- chore: 更新文档
- todo: RSA加解密调整

V0.4.1
------

Released in 2019-04-21

-  fix: 修复python2.7下RSAEncrypt的plaintext参数编码
-  feat: 新增RSADecrypt参数sentinel
-  docs: 更新js和api说明

V0.4.0
------

Released in 2019-04-05

-  fix & feat: set aes output/input format, support hex and base64

V0.3.0
------

Released in 2019-01-22

-  生成、导入RSA私钥时可以设置密码
-  命令行参数化，可设置长度、密码并写入PEM文件
-  自定义签名算法：md5、sha1、sha256
-  RSA加密、解密弃用rsa包，改用pycryptdome的PKCS1_v1_5
-  注意：Pycrypto、Pycryptodome将弃用！

V0.2.4
------

Released in 2019-01-18

-  修复部分编码问题
-  增加sha1、sha256签名

V0.2.3
------

Released in 2019-01-16

-  修复部分编码问题
-  加密库从pycrypto改为pycryptodomex
-  支持pypy

V0.2.2
------

Released in 2019-01-15

-  支持python3

V0.2.1
------

Released in 2019-01-11

-  修复签名排序bug

V0.2.0
------

Released in 2019-01-08

-  修改签名bug
-  增加签名可选参数实现关键字段签名、不签名等
-  优化加密、解密类，简化用户操作，方便调用（不兼容0.1.0版本）

V0.1.0
------

Released in 2019-01-04

-  首发版本
-  RSA密钥对生成
-  RSA加密、解密
-  AES加密、解密
-  加密通信流程初步完成：客户端上传数据加密 ==> 服务端获取数据解密 ==> 服务端返回数据加密 ==> 客户端获取数据解密
