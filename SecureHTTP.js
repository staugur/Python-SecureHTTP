/*!
 * @Name: SecureHTTP.js
 * @Author: staugur
 * @Version: 0.1.0
 * @Pypi: 0.2.0 ~ 0.3.0+
 * @GitHub: https://github.com/staugur/Python-SecureHTTP
 * @Document: https://python-securehttp.readthedocs.io/#securehttp-js
 * @Require: brix/crypto-js、travist/jsencrypt
 * @Date: 2019-01-29
 */

"use strict";

function AESEncrypt(key, plaintext) {
    /*
     * [encrypt 加密]
     * @return {[type]} [description]
     */
    var iv = key.substring(0, 16);
    var generator = CryptoJS.AES.encrypt(plaintext, CryptoJS.enc.Utf8.parse(key), {
        iv: CryptoJS.enc.Utf8.parse(iv),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    });
    //hex格式密文
    var ciphertext = generator.ciphertext.toString();
    //hex转为base64
    return CryptoJS.enc.Base64.stringify(CryptoJS.enc.Hex.parse(ciphertext));
}

function AESDecrypt(key, ciphertext) {
    /*
     * [decrypt 解密]
     * @return {[type]} [description]
     */
    var iv = key.substring(0, 16);
    var generator = CryptoJS.AES.decrypt(ciphertext.toString(), CryptoJS.enc.Utf8.parse(key), {
        iv: CryptoJS.enc.Utf8.parse(iv),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    });
    return generator.toString(CryptoJS.enc.Utf8);
}

function RSAEncrypt(pubkey, plaintext) {
    var encrypt = new JSEncrypt();
    encrypt.setPublicKey(pubkey);
    return encrypt.encrypt(plaintext);
}

class EncryptedCommunicationBrowser {

    constructor(PublicKey) {
        //AESKey自动生成
        this.AESKey = this._randomWord(32);
        //pkcs1或pkcs8格式公钥
        this.PublicKey = PublicKey;
    }

    _randomWord(length) {
        /*
         * randomWord 产生任意长度随机字母数字组合
         */
        let str = "",
            range = length,
            arr = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
                'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
                'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
                '-', '.', '~', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', ':', '<', '>', '?'
            ];
        for (let i = 0; i < range; i++) {
            var pos = Math.round(Math.random() * (arr.length - 1));
            str += arr[pos];
        }
        return str;
    }

    _getNowFormatDate() {
        var date = new Date();
        var seperator1 = "-";
        var seperator2 = ":";
        var month = date.getMonth() + 1;
        var strDate = date.getDate();
        if (month >= 1 && month <= 9) {
            month = "0" + month;
        }
        if (strDate >= 0 && strDate <= 9) {
            strDate = "0" + strDate;
        }
        var currentdate = date.getFullYear() + seperator1 + month + seperator1 + strDate +
            "T" + date.getHours() + seperator2 + date.getMinutes() +
            seperator2 + date.getSeconds() + "Z";
        return currentdate;
    }

    _sign(params, meta) {
        /*
            @params object: uri请求参数(包含除signature外的公共参数)
        */
        if (typeof(params) != "object" || typeof(meta) != "object") {
            console.error("params or meta is not an object");
            return false;
        }
        var signIndex = meta["SignatureIndex"];
        if (!signIndex) {
            console.error('Invalid signIndex');
            return false;
        }
        var signIndex = signIndex.split(/\s*,\s*/);
        var data = {};
        for (var i = 0; i < signIndex.length; i++) {
            var item = signIndex[i];
            if (!params.hasOwnProperty(item)) {
                throw Error("Signature index(" + item + ") does not existx");
            } else {
                data[item] = params[item];
            }
        }
        // 添加加公共参数
        for (var i in meta) {
            data[i] = meta[i];
        }
        // NO.1 参数排序
        var _my_sorted = Object.keys(data).sort();
        // NO.2 排序后拼接字符串
        var canonicalizedQueryString = '';
        for (var _i in _my_sorted) {
            canonicalizedQueryString += this._percent_encode(_my_sorted[_i]) + '=' + this._percent_encode(data[_my_sorted[_i]]) + '&';
        }
        // NO.3 加密返回签名: signature
        return CryptoJS.MD5(canonicalizedQueryString).toString();
    }

    _percent_encode(encodeStr) {
        try {
            encodeStr = JSON.stringify(encodeStr);
        } catch (err) {
            throw Error(err);
        }
        var res = encodeURIComponent(encodeStr);
        res = res.replace('+', '%20').replace('*', '%2A').replace('%7E', '~');
        return res;
    }

    browserEncrypt(post, signIndex) {
        if (typeof(post) != "object") {
            console.error("post is not an object");
            return false;
        }
        if (!signIndex) {
            console.error('Invalid signIndex');
            return false;
        }
        //元数据
        var metaData = {
            Timestamp: this._getNowFormatDate(),
            SignatureVersion: "v1",
            SignatureMethod: "md5",
            SignatureIndex: signIndex
        };
        metaData["Signature"] = this._sign(post, metaData);
        post["__meta__"] = metaData;
        var JsonAESEncryptedData = AESEncrypt(this.AESKey, JSON.stringify(post));
        return {
            key: RSAEncrypt(this.PublicKey, this.AESKey),
            value: JsonAESEncryptedData
        };
    }

    browserDecrypt(encryptedRespData) {
        if (typeof(encryptedRespData) != "object") {
            console.error("encryptedRespData is not an object");
            return false;
        }
        if (encryptedRespData.hasOwnProperty("data")) {
            var JsonAESEncryptedData = encryptedRespData["data"];
            var respData = JSON.parse(AESDecrypt(this.AESKey, JsonAESEncryptedData));
            var metaData = respData["__meta__"];
            delete respData["__meta__"];
            var Signature = metaData["Signature"];
            delete metaData["Signature"];
            if (Signature === this._sign(respData, metaData)) {
                return respData;
            } else {
                throw Error("Signature verification failed");
            }
        } else {
            throw Error("Invalid encrypted resp data");
        }
    }

}