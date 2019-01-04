#python2,python3,pypy
import hmac
import hashlib

hmac_sha256 = lambda message: hmac.new(key=b"secret", msg=message, digestmod=hashlib.sha256).hexdigest()
print(hmac_sha256(b"Message"))
