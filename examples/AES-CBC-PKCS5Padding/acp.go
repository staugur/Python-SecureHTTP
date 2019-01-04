package main

import (
    "crypto/aes"
    "crypto/cipher"
    "bytes"
    //"encoding/base64"
    "encoding/hex"
    "fmt"
)

var key = []byte("secretsecretsecr")

var iv = []byte("secretsecretsecr")

type AES_CBC struct {

}

func main(){
    plainText := []byte("Message")
    fmt.Println("plain:", string(plainText))

    //加密串
    cipherText,_ := Encrypt(plainText)
    fmt.Println("cipher:", cipherText)

    //解密串
    newPlain,_ := Decrypt(cipherText)
    fmt.Println("new plain:", newPlain)
}

func Encrypt(origData []byte) (string, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }
    blockSize := block.BlockSize()
    origData = PKCS5Padding(origData, blockSize)
    // origData = ZeroPadding(origData, block.BlockSize())
    blockMode := cipher.NewCBCEncrypter(block, iv)
    crypted := make([]byte, len(origData))

    blockMode.CryptBlocks(crypted, origData)
    //输出16进制
    return hex.EncodeToString(crypted),nil
    //输出base64编码
    //return base64.StdEncoding.EncodeToString(crypted), nil
}

func Decrypt(crypted string) (string, error) {
    //16进制时用此方法解码
    decodeData, err := hex.DecodeString(crypted)
    //base64编码时用此方法解码
    //decodeData,err:=base64.StdEncoding.DecodeString(crypted)
    if err != nil {
        return "",err
    }
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }
    //blockSize := block.BlockSize()
    blockMode := cipher.NewCBCDecrypter(block, iv)
    origData := make([]byte, len(decodeData))
    blockMode.CryptBlocks(origData, decodeData)
    origData = PKCS5UnPadding(origData)
    // origData = ZeroUnPadding(origData)
    return string(origData), nil
}

func ZeroPadding(ciphertext []byte, blockSize int) []byte {
    padding := blockSize - len(ciphertext) % blockSize
    padtext := bytes.Repeat([]byte{0}, padding)
    return append(ciphertext, padtext...)
}

func ZeroUnPadding(origData []byte) []byte {
    length := len(origData)
    unpadding := int(origData[length - 1])
    return origData[:(length - unpadding)]
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
    padding := blockSize - len(ciphertext) % blockSize
    padtext := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
    length := len(origData)
    // 去掉最后一个字节 unpadding 次
    unpadding := int(origData[length - 1])
    return origData[:(length - unpadding)]
}
