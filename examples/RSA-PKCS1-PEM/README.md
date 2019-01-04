实现：
```
    算法：RSA
    填充：RSA_PKCS1_PADDING
    密钥格式：符合PKCS#1规范，密钥对采用PEM形式
```

生成密钥对： 
```
    1. https://www.cnblogs.com/hongdada/p/8295526.html
    2. https://www.jianshu.com/p/9da812e0b8d0
    3. 通过执行shell脚本generate_rsa_keys.sh生成pkcs1密钥对及对应的pkcs8密钥对，自主选择某种格式私钥
```

选择密钥对：
```
    经过go、php、py三个例子，建议私钥使用pkcs1格式、公钥使用pkcs8格式
```

不同规范PEM格式如下：
```
RSA Public/Private Key (PKCS#1)
# 公钥
-----BEGIN RSA PUBLIC KEY-----
-----END RSA PUBLIC KEY-----
# 私钥
-----BEGIN RSA PRIVATE KEY-----
-----END RSA PRIVATE KEY-----
```

Public/Private Key (PKCS#8)
```
# 公钥
-----BEGIN PUBLIC KEY-----
-----END PUBLIC KEY-----
# 私钥
-----BEGIN PRIVATE KEY-----
-----END PRIVATE KEY-----
```