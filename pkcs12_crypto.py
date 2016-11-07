"""
PKCS12 password algorithm

Copyright (c) 2016 Willem Hengeveld <itsme@xs4all.nl>
"""
from __future__ import division, print_function
from Crypto.Hash import SHA as SHA1
from Crypto.Hash import MD5
from Crypto.Cipher import ARC2, DES3, AES
from binascii import *
import struct

# import Crypto.SelfTest
# import Crypto.SelfTest.Cipher.test_ARC2
# print(Crypto.SelfTest.run(module=Crypto.SelfTest.Cipher.test_ARC2))

def sha1(txt):
    return SHA1.new(txt).digest()
def md5(txt):
    return MD5.new(txt).digest()

def rc2(txt, key, iv):
    cipher = ARC2.new(key, ARC2.MODE_CBC, iv, effective_keylen=40)
    return cipher.decrypt(txt)
def des3(txt, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return cipher.decrypt(txt)
def aes(txt, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(txt)


def genkey(salt, id, pasw, iter, wanted):
    # rfc7292 - Appendix B.  Deriving Keys and IVs from Passwords and Salt
    def pkcsfill(data, n):
        return (data * (n//len(data)+1))  [ :n]
    def tonum(data):
        num = 0
        for b in data:
            if type(b)==str:
                b = ord(b)
            num *= 256
            num += b
        return num
    def todata(num, n):
        hex = ("%x" % num).rjust(2*n, '0')
        return a2b_hex(hex[-2*n:])

    blklen = 64
    salt = pkcsfill(salt, blklen)
    pasw = pkcsfill(pasw, blklen)
        
    out = b""
    while len(out)<wanted:
        data = struct.pack("<B", id) * blklen
        data += salt
        data += pasw

        for _ in range(iter):
            data = sha1(data)

        out += data

        increment = tonum(pkcsfill(data, blklen)) + 1

        salt = todata(tonum(salt) + increment, blklen)
        pasw = todata(tonum(pasw) + increment, blklen)


    return out[:wanted]


