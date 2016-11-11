"""
Decrypt a pdf given the pkcs12 cert + password

note that this works only for pdfs in a specific format.
I tested this with encryptedWithCertificateAes128.pdf from the itext distribution

Usage:

    python3 decryptpdf.py encryptedWithCertificateAes128.pdf test.p12 kspass

Copyright (c) 2016 Willem Hengeveld <itsme@xs4all.nl>
"""
from binascii import *
from pdfparser import parsepdf, PdfOperator, UngetStream
from certparse import pkcs12decoder, XXXXdecoder, privdecoder
from der_decoder import bytes2int
from pkcs12_crypto import genkey, des3, rc2, sha1, aes, md5

from Crypto.Cipher import ARC2
import sys
import struct

class empty: pass
args = empty()
args.verbose = args.recurse = args.skiplinks = False

def findtrailer(stk):
    """ searches pdf stack for 'trailer' keyword """
    retnext = False
    for itm in stk:
        if retnext:
            return itm
        if isinstance(itm, PdfOperator) and itm.value==b'trailer':
            retnext = True

pdfname, certname, certpw = sys.argv[1:]
stk, objs = parsepdf(args, UngetStream(open(pdfname, "rb")))

certpw += '\x00'
certpw = certpw.encode('utf-16be')

privkey = usercert = None

with open(certname, "rb") as fh:
    """ tries to decrypt any encrypted blobs from a pkcs12 encoded keybag """
    for (alg, salt, n, data) in pkcs12decoder(fh.read()):
        if alg=='1.2.840.113549.1.12.1.3':
            keysize = 24
        else:
            keysize = 5
        key = genkey(salt, 1, certpw, n, keysize)
        iv = genkey(salt, 2, certpw, n, 8)
        if alg=='1.2.840.113549.1.12.1.3':
            data = des3(data, key, iv)
            print("priv", b2a_hex(data[-16:]))
            privkey = privdecoder(data)
        else:
            data = rc2(data, key, iv)
            print("cert", b2a_hex(data[-16:]))
            usercert = data

trailer = findtrailer(stk)
encref = trailer['Encrypt']
enc = encref.dereference(objs)
cf = enc['CF']
filt = cf['DefaultCryptFilter']
rcp = filt['Recipients']

def b2int(data):
    return int(b2a_hex(data),16)
def i2bin(num, l):
    x = ("%0"+str(l*2)+"x") % num
    return a2b_hex(x)

def objkey(oid, gen, mkey):
    """ generate decryption key for the specified object """
    return md5(mkey[:16] + struct.pack("<HBH", oid&0xFFFF, oid>>16, gen) + b'sAlT')

for (rsadata, symalg, num, iv, symdata) in XXXXdecoder(rcp[0].asbytes()):
    decrypted = i2bin(pow(b2int(rsadata), privkey[2], privkey[0]), len(rsadata))
    if decrypted[:2] != b'\x00\x02':
        raise Exception("failed rsa decrypted")
    key = decrypted[-16:]

    # ... should read algorithm from the rcp value
    cipher = ARC2.new(key, ARC2.MODE_CBC, iv, effective_keylen=128)
    seedperms = cipher.decrypt(symdata)

    seed = seedperms[:20]
    perms = struct.unpack(">L", seedperms[20:24])

    print("seed = %s" % b2a_hex(seed))

    mkey = sha1(seed + rcp[0].asbytes())
    print("mkey=", b2a_hex(mkey))

# as an example decrypt the Info dictionary
inforef = trailer['Info']
infodict = inforef.dereference(objs)
for k in ('Author', 'CreationDate', 'Creator', 'ModDate', 'Producer'):
    s = infodict[k].asbytes()
    print(k, aes(s[16:], objkey(inforef.oid,inforef.gen,mkey), s[:16]))

