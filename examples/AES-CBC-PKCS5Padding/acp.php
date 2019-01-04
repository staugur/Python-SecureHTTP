<?php
/*
+--------------------------------------------------------------------------
|   由于在php7.1之后mcrypt_encrypt会被废弃，因此使用openssl_encrypt方法来替换。
|   AES CBC PKCS5padding 方式加解密
|   ========================================
|   by Focus
|   ========================================
|
|   https://segmentfault.com/a/1190000010128665
+---------------------------------------------------------------------------
*/

class OpensslEncryptHelper {
    /**向量
     * @var string
    */
    const IV = "secretsecretsecr"; //16位
    
    /**
     * 默认秘钥
     */
    const KEY = 'secretsecretsecr'; //16位
    
    /**
     * 解密字符串
     * @param string $data 要解密的字符串
     * @param string $key 加密key
     * @return string
     */
    public static function decryptWithOpenssl($data, $key = self::KEY, $iv = self::IV) {
        # 解密16进制的$data
        return openssl_decrypt(hex2bin($data) , "AES-128-CBC", $key, OPENSSL_RAW_DATA, $iv);
        # 解密base64编码的$data
        #return openssl_decrypt(base64_decode($data) , "AES-128-CBC", $key, OPENSSL_RAW_DATA, $iv);
    }
    /**
     * 加密字符串
     * 参考网站： https://segmentfault.com/q/1010000009624263
     * @param string $data 要加密的字符串
     * @param string $key 加密key
     * @return string
     */
    public static function encryptWithOpenssl($data, $key = self::KEY, $iv = self::IV) {
        # 返回16进制的加密串
        return bin2hex(openssl_encrypt($data, "AES-128-CBC", $key, OPENSSL_RAW_DATA, $iv));
        # 返回base64编码的加密串
        #return base64_encode(openssl_encrypt($data, "AES-128-CBC", $key, OPENSSL_RAW_DATA, $iv));
    }
}
$a = new OpensslEncryptHelper();
$rst = $a->encryptWithOpenssl('Message');
echo ($rst);
echo ("\n");
$rst2 = $a->decryptWithOpenssl($rst);
echo ($rst2);
?>

