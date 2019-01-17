package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
)

var decrypted string

func init() {
	flag.StringVar(&decrypted, "d", "", "加密过的数据")
	flag.Parse()
}

func main() {
	var data []byte
	var err error
	if decrypted != "" {
		data, err = base64.StdEncoding.DecodeString(decrypted)
		if err != nil {
			panic(err)
		}
	} else {
		data, err = RsaEncrypt([]byte("Message"))
		if err != nil {
			panic(err)
		}
		fmt.Println("rsa encrypt base64: " + base64.StdEncoding.EncodeToString(data))
	}
	origData, err := RsaDecrypt(data)
	if err != nil {
		panic(err)
	}
	fmt.Println("rsa decrypted: " + string(origData))
}

// 适用pkcs1私钥
var privateKey = []byte(`
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`)

// 适用pkcs8公钥
var publicKey = []byte(`
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDK7sG7nZnIUAfl6Hf7UwYwdPKu
UjslnB3xAWLZvL295i1e2+tDjN7Eli5yIbhxePxAE760tEAz+6UcWPRGDdlshNRo
Gp4lWob1qMEg/7g8rxvhHioUFjnNE0kRy2OJJ9OQSViUagXs09qeqvs0AssOiGup
S3CJ/G1Dy8TxcHHbwwIDAQAB
-----END PUBLIC KEY-----
`)

// 加密
func RsaEncrypt(origData []byte) ([]byte, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
}

// 解密
func RsaDecrypt(ciphertext []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error!")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
}
