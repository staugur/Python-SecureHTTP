# -*- coding: utf-8 -*-

from flask import Flask, jsonify, request
from SecureHTTP import EncryptedCommunicationServer, generate_rsa_keys

(pubkey, privkey) = generate_rsa_keys(incall=True)

app = Flask(__name__)
app.config['TESTING'] = True

@app.route("/", methods=["POST"])
def index():
    sc = EncryptedCommunicationServer()
    (data, AESKey) = sc.serverDecrypt(privkey, request.form)
    resp = sc.serverEncrypt(AESKey, data)
    return jsonify(resp)

if __name__ == "__main__":
    app.run()