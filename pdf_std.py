"""
Script i wrote while figuring out how the 'old' PDF encryption algorithm works.

see  qpdf/libqpdf/QPDF_encryption.cc

Author: Willem Hengeveld <itsme@xs4all.nl>

"""
from Crypto.Hash import MD5, SHA256
from Crypto.Cipher import ARC4, AES
import struct
from binascii import b2a_hex, a2b_hex
from pdfparser import UngetStream, EnumeratePaths, parsepdf, PdfOperator, PdfStream

class empty: pass
args = empty()
args.verbose = args.recurse = args.skiplinks = False


pwpadding = a2b_hex('28BF4E5E4E758A4164004E56FFFA01082E2E00B6D0683E802F0CA9FE6453697A')

def md5(x):
    return MD5.new(x).digest()
def sha256(x):
    return SHA256.new(x).digest()
def aes(txt, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(txt)

def rc4(x, k):
    return ARC4.new(k).encrypt(x)

def calcpdfkey(mkey, oid, gen, useaes):
    #algo31
    suffix = b'sAlT' if useaes else b''
    return md5(mkey + struct.pack("<HBH", oid&0xFFFF, oid>>16, gen) + suffix)

def padpw(passwd):
    return (passwd+pwpadding)[:32]

# computeGlobalEncryptionKey in StandardHandlerUsingStandard40.java
# compute_encryption_key_from_password in QPDF_encryption.cc

# todo: recover_encryption_key_with_password ( for V>=5 )
def calcpwkey(passwd, ownerhash, perms, fileid, has_encrypted_metadata, revision, keylen=5):
    # algo32
    suffix = b'\xff\xff\xff\xff' if has_encrypted_metadata else b''
    print("hashing %s + %s + %s + %s + %s" % (b2a_hex(padpw(passwd)), b2a_hex(ownerhash[:32]), b2a_hex(struct.pack("<L",perms)), b2a_hex(fileid), b2a_hex(suffix)))
    h = md5(padpw(passwd) + ownerhash[:32] + struct.pack("<L", perms) + fileid + suffix)
    if revision>=3:
        for _ in range(50):
            h = md5(h[:keylen])
    return h[:keylen]


def hash5(pw, salt, udata):
    return sha256( pw + salt + udata)

def aesdecrypt(key, data):
    iv = b"\x00" * 16
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(data)

# recover_encryption_key_with_password
def calcpwkey5(pw, howner, ownerenc, huser, userenc, perms, fileid, revision, keylen):
    if ownerhash5(pw, huser, howner)==howner[:32]:
        print("found owner pass")
        salt = howner[40:48]
        userdata = huser[:48]
        encfilekey = ownerenc[:32]
    elif userhash5(pw, huser) == huser[:32]:
        print("found user pass")
        salt = huser[40:48]
        userdata = b''
        encfilekey = userenc[:32]
    else:
        print("unknown pass")
        return

    print("salt=%s, ud=%s, enc=%s" % (b2a_hex(salt), b2a_hex(userdata), b2a_hex(encfilekey)))

    immkey = hash5(pw, salt, userdata)
    filekey = aesdecrypt(immkey, encfilekey)
    #permscheck = aesencryot(filekey, false, perms, 12)
    # todo: permscheck

    print("immkey=%s, filekey=%s" % (b2a_hex(immkey), b2a_hex(filekey)))

    return filekey

def ownerhash5(pw, huser, howner):
    return hash5(ownerpass, howner[32:40], huser[:48])

def userhash5(pw, huser):
    return hash5(pw, huser[32:40], b'')

def xorbytes(data, xorval):
    return bytes([_ ^ xorval for _ in data])

# computeOwnerKey in StandardHandlerUsingStandard40.java
#  compute_O_rc4_key + compute_O_value in QPDF_encryption.cc
#  works for rev=1..4
def calcownerhash(ownerpasswd, userpasswd, revision, keylen):
    # algo33
    h = md5(padpw(ownerpasswd))
    if revision>=3:
        for _ in range(50):
            h = md5(h)
    rc4key = h[:keylen]
    x = padpw(userpasswd)
    niter = 20 if revision>=3 else 1
    for i in range(niter):
        x = rc4(x, xorbytes(rc4key, i))
    return x

# computeUserKey in StandardHandlerUsingStandard40.java
# compute_U_value_R3
def calcuserhash(rc4key, fileid, revision):
    # algo34+algo35
    print("rc4key=", b2a_hex(rc4key))
    if revision<3:
        # compute_U_value_R2
        return rc4(pwpadding, rc4key)
    x = md5(pwpadding + fileid)
    for i in range(20):
        x = rc4(x, xorbytes(rc4key, i))
    return x + b'\x00' * 16

def searchobjs(objs):
    for itm in objs.values():
        for o in itm.body:
            if isinstance(o, PdfStream) and 'ID' in o.params and 'Encrypt' in o.params:
                return o.params

def getencryptioninfo(fh):
    stk, objs = parsepdf(args, fh)

    trailer = findtrailer(stk)
    if not trailer:
        trailer = searchobjs(objs)
    if not trailer:
        raise Exception("no trailer")
    idarr = trailer['ID']
    encref = trailer['Encrypt']
    if not encref:
        raise Exception("no encryption dict")
    enc = encref.dereference(objs)
    v = enc['V']
    r = enc['R']
    p = enc['P']
    o = enc['O']
    oe = enc['OE']
    u = enc['U']
    ue = enc['UE']

    inforef = trailer['Info']
    if not inforef:
        raise Exception("no inforef")
    info = inforef.dereference(objs)

    # todo - what is enc.get(b'Perms') ?

    o = o.asbytes() if o else None
    u = u.asbytes() if u else None
    oe = oe.asbytes() if oe else None
    ue = ue.asbytes() if ue else None
    p = p.asint() if p else None

    return idarr[0].asbytes(), o, oe, u, ue, p, v.asint(), r.asint(), inforef, info


def findtrailer(stk):
    """ searches pdf stack for 'trailer' keyword """
    retnext = False
    for itm in stk:
        if retnext:
            return itm
        if isinstance(itm, PdfOperator) and itm.value==b'trailer':
            retnext = True


userpass = b""
ownerpass = b""

def processfile(fh):
    fileid, howner, ownerenc, huser, userenc, perms, version, revision, inforef, info = getencryptioninfo(UngetStream(fh))
    if howner is None:
        return

    print("fileid=", b2a_hex(fileid))
    print("howner=", b2a_hex(howner))
    print("huser=", b2a_hex(huser))
    print("rev=%d, ver=%d" % (revision, version))
    if perms and perms<0:  perms += 0x100000000

    has_encrypted_metadata = False

    keylen = 5 if revision<3 else 16

    if version<5:
        rc4key = calcpwkey(userpass, howner, perms, fileid, has_encrypted_metadata, revision, keylen)
    else:
        rc4key = calcpwkey5(ownerpass, howner, ownerenc, huser, userenc, perms, fileid, revision, keylen)

    if not rc4key:
        return

    uh = calcuserhash(rc4key, fileid, revision)
    if uh!=huser:
        print("uh=", b2a_hex(uh), "expect=", b2a_hex(huser))
    else:
        print("User is known")

    oh = calcownerhash(ownerpass, userpass, revision, keylen)
    if oh!=howner:
        print("oh=", b2a_hex(oh), "expect=", b2a_hex(howner))
    else:
        print("Owner is known")

    # works for 3.2,  4.4
    useaes = revision>=4
    # todo: check CFM for 'AESV2'
    infokey = calcpdfkey(rc4key, inforef.oid, inforef.gen, useaes)
    for k in ('Author', 'CreationDate', 'Creator', 'ModDate', 'Producer', 'Keywords', 'Subject', 'Title', 'Perms'):
        v = info.get(k)
        if v:
            if useaes:
                dec = aes(v.asbytes(), infokey, b'\x00' * 16)
            else:
                dec = rc4(v.asbytes(), infokey)
            print(k, dec)


import argparse
parser = argparse.ArgumentParser(description='pdf_std')
parser.add_argument('--debug', action='count')
parser.add_argument('--verbose', '-v', action='count', default=0)
parser.add_argument('--recurse', '-r', action='store_true', help='recurse into directories')
parser.add_argument('--skiplinks', '-L', action='store_true', help='skip symbolic links')
parser.add_argument('--user', '-u',  type=str, help='the user password')
parser.add_argument('--owner', '-o', type=str, help='the owner password')
parser.add_argument('--danglingfatal', '-d', action='store_true', help='error on dangling endobj, bracket')

parser.add_argument('FILES', type=str, nargs='+', help='Files')
args = parser.parse_args()

if args.user: userpass = args.user.encode('utf-8')
if args.owner: ownerpass = args.owner.encode('utf-8')


for fn in EnumeratePaths(args, args.FILES):
    print("==>", fn, "<==")
    try:
        with open(fn, "rb") as fh:
            processfile(fh)
    except Exception as e:
        print("ERROR %s" % e)
        if args.debug:
            raise

