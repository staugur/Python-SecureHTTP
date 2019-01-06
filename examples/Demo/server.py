# -*- coding: utf-8 -*-
from flask import Flask, jsonify, request
from SecureHTTP import EncryptedCommunicationServer

app = Flask(__name__)
privkey = """-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC0nKhCfYfMYxCWI0/gMiiTxJbHp73Bwff3twyh5/ygLIuSHv7U
mRnljiPVG9W/OiOx9NXGldNTbSZexq3FU/PWTtPqrtwmktCTAl2kpPzYEwyQgtAO
HZ4MXuuuRarXYxfcZLm4par4E5bgTzx9DTm9Egc01uWkwg3L5bYHMlUE9wIDAQAB
AoGAYriWR/GxfohPkqEukc8Y2txDxlHrqLLLRT1qzDyvmyV+DJqgk7gzrYPqFhwm
02WGCUlYaDmQzzMEHB3g8dEXoApjdeO3Pu+QSJskq4Lvgh0HeZNzhL+5R6knHVzq
cVC4fsjuLkVLNPxkgTF1IKeZsJlKH10d9M8fJ3L/zjCAjEECQQDEdizryMqttD8M
76LqqvIvZzlRFU/U/LzVCmq8TA+Wr/70oynbYN3hVZpS+z645YkQyebx+X/1kTAC
9lLTwzfRAkEA61jWORkklwi+2FWloJI1YemHFUdeoHWxdMOH6eCSk+SaQ+4zSnUi
3/0dEKmuS3NYjx6vKa0VgxB+UAmiGdRqRwJAaRK3RcfXNn3/dsC3xoB1FQtFKWuX
jdc6e0qd+WVItRQd7ONTIKS3Jqws5JLBYgxJeXQyk1oYqNLk9cCeXem78QJAaoHS
uRZq27tGeysPgMKKTBxeWL/q0B1TSO9wY+SREUMkmVeEeM7YEJxA+hiAW38A9gxB
40+Ea8McFua1KJFb4wJBAJ8W6HmDbO1pGhEdhzZ7IkiH5JCBrwZk2NVCYfZccjtI
sqgEktcytOWXQ+qnOxKkP9Zk32Zanp5o+CCZJqYiBYU=
-----END RSA PRIVATE KEY-----"""

@app.route("/", methods=["POST"])
def index():
    sc = EncryptedCommunicationServer()
    print(request.get_json())
    post = request.json
    print("server post: %s" %post)
    print("serverDecrypt: %s" %sc.serverDecrypt(privkey, post))
    return ""

    try:
        (data, AESKey) = sc.serverDecrypt(privkey, post)
    except Exception,e:
    	raise
    else:
        resp = sc.serverEncrypt(AESKey, data)
        return jsonify(resp)
    return jsonify(a=1)

if __name__ == "__main__":
    app.run(port=5000, debug=True)