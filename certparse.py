"""
parse various types of pkcsX.X asn1-DER encoded objects

Copyright (c) 2016 Willem Hengeveld <itsme@xs4all.nl>
"""
from __future__ import division, print_function
from der_decoder import  *
import sys
if sys.version_info < (3, 0):
    bytes = bytearray


def oidpack(dotted):
    """ convert dotted oid to binary representation """
    def packnum(x):
        if x==0:
            return struct.pack("B", 0)

        packed = []
        while x:
            packed.append((x&127)|128)
            x >>= 7
        packed[0] &= 0x7f
        return struct.pack("%dB" % len(packed), *packed[::-1])

    nums =  (int(_) for _ in dotted.split('.'))
    first = next(nums) ; second = next(nums)
    bits = struct.pack("B", first*40 + second)
    for x in nums:
        bits += packnum(x)
    return bits


def oidunpack(data):
    """ convert binary oid to dotted notation """
    def oidgen(data):
        if len(data)==0:
            return
        data = bytes(data)
        first = data[0]
        yield int(first/40)
        yield first%40
        id = 0
        for b in data[1:]:
            byte = b
            id <<= 7
            id |= byte&127
            if (byte&128)==0:
                yield id
                id = 0
    return ".".join(str(_) for _ in oidgen(data))


def x509decoder(data):
    """
    parses X509 certificate
    returns (serial, algo, issuer, validity, subject, pubkey, extended)
    """
    t, l, v = get_tlv(data)
    if t!=0x30: raise Exception("expected SEQ")
    if l<len(data): raise Exception("cert too long")
    body, signingalg, signature = der_decode(v)
    items = der_decode(body[1])
    version = 0
    if items[0][1]==0xa0:
        version = items.pop()

    if len(items)==6:
        items.append(None)
    return items


def privdecoder(data):
    """
    parses private rsa key
    returns (modulus, publicexponent, privateexponent)
    """
    t, l, v = get_tlv(data)
    ver, algo, params = der_decode(v)
    t, l, v = get_tlv(params[1])
    nums = der_decode(v)
    mod, pubexp, privexp = nums[1:4]

    return bytes2int(mod[1]), bytes2int(pubexp[1]), bytes2int(privexp[1])


def pkcs12decoder(data):
    """
    parses pkcs12 object
    yields the encrypted contents.
    """
    t, l, v = get_tlv(data)
    if t!=0x30: raise Exception("expected SEQ")
    if l<len(data): raise Exception("pkcs12 too long")
    version, content, macdata = der_decode(v)
    if version[1]!=b'\x03': raise Exception("expected pkcs12 v3")
    yield from recursive_decoder(content[1])


def XXXXdecoder(data):
    t, l, v = get_tlv(data)
    if t!=0x30: raise Exception("expected SEQ")
    if l<len(data): raise Exception("pkcs??? too long")

    yield from recursive_decoder(v)


def decode_int(data):
    if len(data)==1: return struct.unpack(">B", data)[0]
    if len(data)==2: return struct.unpack(">H", data)[0]
    if len(data)==4: return struct.unpack(">L", data)[0]
    raise Exception("unsupported int type")


def pkcs8decoder(data):
    """
    parses pkcs8 object
    yields (algorithm-oid, iv, itercount, data)
    """
    t, l, v = get_tlv(data)
    algo, encdata = der_decode(v)
    algoid, params = der_decode(algo[1])
    iv, itercount = der_decode(params[1])
    #print("PKCS8 - alg=", oidunpack(algoid[1]), "iv=", iv, "iter=", itercount, "cont=", encdata)
    yield (oidunpack(algoid[1]), iv[1], decode_int(itercount[1]), encdata[1])


def encrypteddatadecoder(data):
    """
    parses EncryptedData object
    yields (algorithm-oid, iv, itercount, data)
    """
    t, l, v = get_tlv(data)
    version, content = der_decode(v)
    ctyp, algo, content = der_decode(content[1])
    algoid, params = der_decode(algo[1])
    iv, itercount = der_decode(params[1])
    #print("PKCS7 - type=",oidunpack(ctyp[1]), "alg=", oidunpack(algoid[1]), "iv=", iv, "iter=", itercount, "cont=", content)
    yield (oidunpack(algoid[1]), iv[1], decode_int(itercount[1]), content[1])


def envelopeddatadecoder(data):
    """
    parses EnvelopedData object
    yields (rsaparams, alg, num, iv, data)
    """
    t, l, v = get_tlv(data)
    version, rsaenc, symenc= der_decode(v)
    t, l, v = get_tlv(rsaenc[1])
    ver2, userid, algo, rsadata = der_decode(v)

    ctype, symalg, symdata = der_decode(symenc[1])
    symalg, symparams = der_decode(symalg[1])
    num, iv = der_decode(symparams[1])
    yield (rsadata[1], symalg[1], num[1], iv[1], symdata[1])


def recursive_decoder(data):
    """
    recurse through pkcs12/pkcs7/pkcs8 data,
    yielding the interesting bits.
    """
    items = der_decode(data)

    contenttype, content = items[:2]
    if content[0]!=0xa0: raise Exception("expected CONTEXT[0]")
    if contenttype[1]==oidpack("1.2.840.113549.1.7.1"):
        t, l, v = get_tlv(content[1])
        if t!=4: raise Exception("expected octetstring")
        t, l, v = get_tlv(v)
        if t!=0x30: raise Exception("expected sequence")
        for item in der_decode(v):
            yield from recursive_decoder(item[1])
    elif contenttype[1]==oidpack("1.2.840.113549.1.12.10.1.2"):
        yield from pkcs8decoder(content[1])
    elif contenttype[1]==oidpack("1.2.840.113549.1.7.6"):
        yield from encrypteddatadecoder(content[1])
    elif contenttype[1]==oidpack("1.2.840.113549.1.7.3"):
        yield from envelopeddatadecoder(content[1])


if __name__=="__main__":
    """ When called as a script: analyze the arguments as if it is pkcs12 data """
    if len(sys.argv)==1:
        if sys.version_info < (3, 0):
            stdin = sys.stdin
        else:
            stdin = sys.stdin.buffer
        data = stdin.read()
        for (alg, iv, n, data) in pkcs12decoder(data):
            print(alg, iv, n, data)
    else:
        for fn in sys.argv[1:]:
            print("==>", fn, "<==")
            try:
                with open(fn, "rb") as fh:
                    data = fh.read()
                    for (alg, iv, n, data) in pkcs12decoder(data):
                        print(alg, iv, n, data)
            except Exception as e:
                print(e)
