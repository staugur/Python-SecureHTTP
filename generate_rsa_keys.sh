#!/bin/bash
#
#使用openssl生成RSA密钥对
#

function genRSA() {
    #参数：密钥长度
    length=$1
    if [ -z "$length" ];then
        length=2048
    fi

    #参数：定义名称
    pkcs1_private=pkcs1_private.pem
    pkcs1_public=pkcs1_public.pem
    pkcs8_private=pkcs8_private.pem
    pkcs8_public=pkcs8_public.pem

    #NO1. 生成pkcs1私钥
    openssl genrsa -out $pkcs1_private $length
    #NO2. PKCS1私钥转化为PKCS8私钥
    openssl pkcs8 -topk8 -inform PEM -in $pkcs1_private -outform pem -nocrypt -out $pkcs8_private
    #NO3. PKCS1私钥生成公钥（提取PEM RSAPublicKey格式公钥）
    openssl rsa -in $pkcs1_private -pubout -RSAPublicKey_out -out $pkcs1_public
    #NO3. PKCS8私钥生成公钥（提取PEM格式公钥）
    openssl rsa -in $pkcs8_private -pubout -out $pkcs8_public
    #备注：以上两个私钥内容应该是一致的
}

genRSA $1