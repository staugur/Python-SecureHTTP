# -*- coding: utf-8 -*-

from flask import Flask, request, render_template, jsonify
from SecureHTTP import RSADecrypt, generate_rsa_keys

app = Flask(__name__)
(pubkey, privkey) = generate_rsa_keys(incall=True)

@app.route('/', methods=["GET", "POST"])
def index():
    if "GET" == request.method:
        return render_template("index.html", pubkey=pubkey)
    elif "POST" == request.method:
        res = dict(code=1, msg=None)
        username = request.form.get("username")
        password = request.form.get("password")
        # decrypt
        try:
            password_ret = RSADecrypt(privkey, password)
        except Exception as e:
            res.update(msg=str(e))
        else:
            app.logger.debug("username:" + username + "\n" + "password:" + password + "\n" + "encryped password: " + password_ret)
            if username and username == "admin" and password_ret and password_ret == "admin":
                res.update(code=0, password=password_ret)
            else:
                res.update(msg="username or password is not match")
        return jsonify(res)

if __name__ == "__main__":
    app.run(debug=True)