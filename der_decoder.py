"""
Functions for decoding DER encoded objects

Copyright (c) 2016 Willem Hengeveld <itsme@xs4all.nl>
"""
from __future__ import division, print_function
import struct
import re
import datetime
def get_int8(b):  return struct.unpack(">B", b)[0]
def get_int16(b): return struct.unpack(">H", b)[0]
def get_int24(b): (a,b)= struct.unpack(">BH", b);  return (a<<16)|b
def get_int32(b): return struct.unpack(">L", b)[0]
def get_int64(b): return struct.unpack(">Q", b)[0]

def get_length(data):
    hdr = get_int8(data[:1])
    if hdr<=0x7F:
        return (hdr, 1)
    elif hdr==0x81:
        return (get_int8(data[1:2]), 2)
    elif hdr==0x82:
        return (get_int16(data[1:3]), 3)
    elif hdr==0x83:
        return (get_int24(data[1:4]), 4)
    elif hdr==0x84:
        return (get_int32(data[1:5]), 5)

    # Note that i am not handling the indefinite length ( 0x80 ) case,
    # which have objects terminated by EOC ( 0x00 )
    raise Exception("unsupported asn1 length %02x" % hdr)

def get_tlv(data):
    if len(data)<2:
        return None
    tag = get_int8(data[:1])
    (vlen, i) = get_length(data[1:5])
    if i+vlen+1>len(data):
        return None
    return (tag, i+vlen+1, data[i+1:i+1+vlen])

def bytes2int(data):
    num = 0

    for b in data:
        if type(b)==str:
            b = ord(b)
        num *= 256
        num += b
    if num>=pow(2, 8*len(data)-1):
        num -= pow(2, 8*len(data))
    return num

def gettime(x):
    #  YYmmddHHMMSS('Z'|[+-]hhmm)              - 0x17: utc time - ITU-T Rec. X.680
    #  YYYYmmddHHMMSS[.uuuuuu]('Z'|[+-]hhmm)   - 0x18: generalized time - ITU-T Rec. X.680
    m = re.match(r'^(\d+)(?:\.(\d+))?(Z|(?:[+-]\d\d(?::?\d\d)+))$', x)
    if not m:
        raise Exception('invalid time format')
    ymdhms = m.group(1) # date+time
    frac   = m.group(2) # fractional seconds
    tzspec = m.group(3) # timezone
    if len(ymdhms)==12:
        # guess century
        century = '20' if ymdhms[0]<'8' else '19'
        ymdhms = century + ymdhms
    if frac:
        usec = int(frac) * pow(10, 6-len(frac))
    else:
        usec = 0

    # todo - implement tzinfo
    ymd = [int(ymdhms[:4])]
    ymd.extend(int(ymdhms[i:i+2],10) for i in range(4,14,2))
    ymd.append(usec)

    return datetime.datetime(*ymd)


# returns list of tuples,
#   either  (tag, value)
#   or      (None, rawdata)   when the data could not be decoded
def der_decode(data):
    items = []
    i = 0
    while i+1<len(data):
        (t,l,v) = get_tlv(data[i:])
        i += l
        items.append((t,v))
    if i!=len(data):
        items.append((None, data[i:]))

    return items

