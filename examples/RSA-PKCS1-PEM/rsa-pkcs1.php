<?php

# 适用pkcs1和pkcs8私钥
$private_key = '-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMruwbudmchQB+Xo
d/tTBjB08q5SOyWcHfEBYtm8vb3mLV7b60OM3sSWLnIhuHF4/EATvrS0QDP7pRxY
9EYN2WyE1GganiVahvWowSD/uDyvG+EeKhQWOc0TSRHLY4kn05BJWJRqBezT2p6q
+zQCyw6Ia6lLcIn8bUPLxPFwcdvDAgMBAAECgYEAjRMeK0eMuOyqEPJjNpypGNa0
Put7otG9HuZPyf6kCXgS4ncQPo2X8CJXd5BpoLjy47jWQtlsKLcwOVy9tFW8Z63I
+TMrnW5IVxBq7Crqn9L9PP+X0cPmkrUKXYVmOlyrgqRlsVeov3xUmfWSW+m1rZaI
rmDvv4TCcM9gzhOm0UECQQD+FH+VWnQMnaOPPCtF2cHWl4zojs2yjKc2WXsEdaG+
j7NEKbDCwdQARV/D9MihDJFYkmhWDxRQQUubck1TecXHAkEAzHdRJRXtqfCpqU8J
eNSqPQAgQ1WunInS3KM/H1+LEGhStFAqjp7nfGYOV6ZZbFgAyCefNpI6zjBu8OMK
Tu2KJQJAeTUOKBGeiuYowIvTmN7ouZZSgh6dwi+XFTZamSYEowOqYToCOOZ+XCK8
LJ75ltqH+9jcLTHEXwTHLMC6YrgUwQJAEERV4ltyQxjwhpXRLRnOSXgfGPxSHgYh
Doi2VuqlB7MlEU9nc11VEWKVNYf4iVQfC82LLy5HG2xjByspAMqJOQJAImloUb89
llXX5rzGyi6gYV1EUd8M8+ZGgqZGnIF05pu3+p6vo+hQzCFe8TqcxvsUP9TKPkYy
tIqps1OxUDeDHQ==
-----END PRIVATE KEY-----';

# 适用pkcs8公钥
$public_key = '-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDK7sG7nZnIUAfl6Hf7UwYwdPKu
UjslnB3xAWLZvL295i1e2+tDjN7Eli5yIbhxePxAE760tEAz+6UcWPRGDdlshNRo
Gp4lWob1qMEg/7g8rxvhHioUFjnNE0kRy2OJJ9OQSViUagXs09qeqvs0AssOiGup
S3CJ/G1Dy8TxcHHbwwIDAQAB
-----END PUBLIC KEY-----';
 
//echo $private_key;
$pi_key =  openssl_pkey_get_private($private_key);//这个函数可用来判断私钥是否是可用的，可用返回资源id Resource id
$pu_key = openssl_pkey_get_public($public_key);//这个函数可用来判断公钥是否是可用的
#print_r($pi_key);echo "\n";
#print_r($pu_key);echo "\n";
 
 
$data = "Message";//原始数据
$encrypted = ""; 
$decrypted = ""; 
 
echo "source data:",$data,"\n";
 
echo "private key encrypt:\n";
 
openssl_private_encrypt($data,$encrypted,$pi_key);//私钥加密
$encrypted = base64_encode($encrypted);//加密后的内容通常含有特殊字符，需要编码转换下，在网络间通过url传输时要注意base64编码是否是url安全的
echo $encrypted,"\n";
 
echo "public key decrypt:\n";
 
openssl_public_decrypt(base64_decode($encrypted),$decrypted,$pu_key);//私钥加密的内容通过公钥可用解密出来
echo $decrypted,"\n";
 
echo "---------------------------------------\n";
echo "public key encrypt:\n";
 
openssl_public_encrypt($data,$encrypted,$pu_key);//公钥加密
$encrypted = base64_encode($encrypted);
echo $encrypted,"\n";
 
echo "private key decrypt:\n";
openssl_private_decrypt(base64_decode($encrypted),$decrypted,$pi_key);//私钥解密
echo $decrypted,"\n";
