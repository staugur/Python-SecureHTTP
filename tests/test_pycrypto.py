# -*- coding: utf-8 -*-
import os
os.system("pip uninstall -y pycryptodomex")
if os.getenv("CODECOV_TOKEN"):
    os.system("pip install pycryptodome")
else:
    os.system("pip install pycrypto")
from test_securehttp import UtilsTest


if __name__ == '__main__':
    import unittest
    unittest.main()


