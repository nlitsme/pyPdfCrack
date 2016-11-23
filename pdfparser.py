"""
Simple pdf parser

Copyright (c) 2016 Willem Hengeveld <itsme@xs4all.nl>


todo: add start offset to items, so we can use startxref and xref information.
some pdfs don't have a trailer, but only a fileoffset from 'startxref'
"""
from __future__ import print_function
import binascii
import struct
import re
import sys
import os
from zlib import decompressobj
if sys.version_info < (3, 0):
    bytes = bytearray
    reload(sys)
    sys.setdefaultencoding('utf-8')

    import scandir
    os.scandir = scandir.scandir

    stdin = sys.stdin
else:
    stdin = sys.stdin.buffer

# objects:

# (string)     - use \ooo, \r\n\t\b\f\(\)\\  for escaping
# <hexdata>

# /name        -  #xx  to indicate hex(0xxx) char in name

# [array]      - sequence of objects
# <<dict>>     - dictionary has even nr of objects

# <</Length ...>>"stream\n"....."\nendstream\n"     -  raw data

# objnum gennr "obj\n"...."\nendobj\n"         - indirect object

# objnum gennr "R"     - refer to object

## note: all parse_XXX functions return the last offset of the item

# todo: { code }   is not yet parsed

def string_nesting_escape(txt):
    for c in "[({})]":
        txt = txt.replace(c, "#%02x" % ord(c))
    return txt
def simple_decode_string(txt):
    return txt.decode('utf-8', 'replace')
def decode_string(txt):
    if txt.startswith(b'\xfe\xff'):
        txt = txt.decode('utf-16be', 'replace')[1:]
        enc = 'utf16be'
    elif txt.startswith(b'\xff\xfe'):
        txt = txt.decode('utf-16le', 'replace')[1:]
        enc = 'utf16le'
    elif txt.startswith(b'\xef\xbb\xbf'):
        txt = txt.decode('utf-8', 'replace')[1:]
        enc = 'utf8'
    else:
        if re.search(b'[\x80-\xff]', txt):
            txt = binascii.b2a_hex(txt)
            enc = 'hex'
        else:
            txt = txt
            enc = 'ascii'
    return "%s:'%s'" % (enc, txt)


class PdfComment:
    def __init__(self, value):
        self.value = value
    def __repr__(self):
        return "PdfComment: %s" % string_nesting_escape(decode_string(self.value))


class PdfString:
    def __init__(self, value):
        self.value = value
    def __repr__(self):
        return "PdfString: %s" % string_nesting_escape(decode_string(self.value))
    def asbytes(self):
        return self.value


class PdfNesting:
    """ represent a nesting token in the pdf token stream """
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "PdfNesting: %s" % string_nesting_escape(simple_decode_string(self.value))

    def isclose(self):
        if self.value.startswith(b'end'):
            return True
        return self.value[0] in b']}>)'
    def closes(self, item):
        if self.value==b'>>' and item.value==b'<<':
            return True
        if self.value==b')' and item.value==b'(':
            return True
        if self.value==b']' and item.value==b'[':
            return True
        if self.value==b'}' and item.value==b'{':
            return True
        if self.value==b'endobj' and item.value==b'obj':
            return True
        return False

class PdfHexdata:
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "PdfHexdata: %s" % self.value
    def asbytes(self):
        return binascii.a2b_hex(self.value)


class PdfName:
    def __init__(self, value):
        self.value = value

    def name(self):
        return self.value.decode('utf-8', 'ignore')
    def __repr__(self):
        return "PdfName: %s" % string_nesting_escape(simple_decode_string(self.value))
    def __eq__(self, rhs):
        if isinstance(rhs, PdfName):
            rhs = self.value
        if type(rhs)==str:
            return self.value == rhs
    def __ne__(self, rhs):
        return not (self==rhs)


class PdfNumber:
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "PdfNumber: %s" % self.value
    def asint(self):
        return int(self.value)
    def asfloat(self):
        return float(self.value)


class PdfOperator:
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "PdfOperator: %s" % self.value

class PdfDictionary:
    def __init__(self, value):
        self.value = value
        self.d = None

    def __repr__(self):
        return "PdfDictionary: %s" % self.value

    def convert(self):
        """ convert dictionary item list to dict """
        if not self.d is None:
            return
        self.d = dict()
        iskey = True
        k = v = None
        for i in self.value:
            if iskey:
                if not isinstance(i, PdfName):
                    raise Exception("dict keys must be names")
                k = i.name()
                iskey = False
            else:
                v = i
                if k in self.d:
                    print("WARNING: duplicate key in dict : %s = %s .. %s" % (k, self.d[k], v))
                self.d[k] = v
                iskey = True

    def get(self, key):
        self.convert()
        if not key in self.d:
            return None
        return self.d[key]

    # make it behave like a dict
    def __contains__(self, key):
        self.convert()
        return item in self.d
    def __getitem__(self, key):
        return self.get(key)
    def __iter__(self):
        self.convert()
        return iter(self.d)



class PdfArray:
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "PdfArray: %s" % self.value

    def __getitem__(self, i):
        return self.value[i]
    def __len__(self):
        return len(self.value)
    def __iter__(self):
        return iter(self.value)

class PdfStream:
    def __init__(self, params, data):
        self.data = data
        self.params = params
    def __repr__(self):
        return "PdfStream: %s" % self.params
    def contents(self):
        filt = self.params['Filter']
        if filt.name() == 'FlateDecode':
            dec = decompressobj(15)
            data = dec.decompress(self.data)
            print(data)
        elif filt:
            print("unknown filter: %s" % filt)
        else:
            print(self.data)


class PdfObject:
    def __init__(self, body):
        self.body = body
    def __repr__(self):
        return "PdfObject: %s" % self.body

class PdfReference:
    def __init__(self, oid, gen):
        self.oid = oid
        self.gen = gen
    def dereference(self, objlist):
        if self.oid not in objlist:
            print("oid=%s:%s" % (self.oid, self.gen))
            raise Exception("unknown object")
        # note: ignoring generation number
        return objlist[self.oid].body[0]
    def __repr__(self):
        return "PdfReference: %05d.%d" % (self.oid, self.gen)


def is_delimiter(c):
    return c in b"{}<>[]()/%"
def is_opening_delimiter(c):
    return c in b"{<[(/%"
def is_whitespace(c):
    return c in b" \t\r\n\f\x00"

def parse_comment(fh):
    cmt = b''
    while True:
        b = fh.read(1)
        if b == b'':
            return cmt
        if b in b"\r\n":
            return cmt
        cmt += b

def parse_string_escape(fh):
    b = fh.read(1)
    if b==b'':
        raise Exception("truncated string escape at EOF")
    if b==b'r': return b'\r'
    if b==b'n': return b'\n'
    if b==b't': return b'\t'
    if b==b'b': return b'\b'
    if b==b'f': return b'\f'
    if b==b'\n': return b''
    if b==b'\r': return b''
    if b in b'01234567':
        digits = b''
        while len(digits)<3 and b in b"01234567":
            digits += b
            b = fh.read(1)
        fh.unget(b)
        return struct.pack("B", int(digits, 8))

    # \\, (, ),   and others
    return b


def parse_string(fh):
    """ read bracketed and escaped (string) from the pdf """
    res = b''
    plevel = 1
    while plevel:
        b = fh.read(1)
        if b==b'':
            raise Exception("truncated string at EOF")

        if b==b'(':
            plevel += 1
        elif b==b')':
            plevel -= 1
            if plevel==0:
                break
        elif b==b'\\':
            b = parse_string_escape(fh)
        res += b
    return res

   
def parse_hexdata(fh):
    def isxdigit(c):
        return c in b"0123456789abcdefABCDEF"
    hexd = b''
    while True:
        b = fh.read(1)
        if b==b'':
            raise Exception("truncated hexstring at EOF")
        if b==b'>':
            return hexd
        if isxdigit(b):
            hexd += b
        elif is_whitespace(b):
            pass
        else:
            raise Exception("unexpected char in hex string: %s at 0x%x" % (b, fh.tell()))

def parse_name(args, fh):
    """ read name-like text from the pdf """
    n = b''
    while True:
        b = fh.read(1)
        if b==b'':
            return n
        if b==b'#':
            b = struct.pack("B", int(fh.read(2), 16))
        elif is_whitespace(b):
            fh.unget(b)
            return n
        elif is_delimiter(b):
            fh.unget(b)
            return n
        n += b

def parse_number(fh):
    """ read number-like text from the pdf """
    n = b''
    while True:
        b = fh.read(1)
        if b == b'':
            return n
        if b not in b"-.0123456789":
            fh.unget(b)
            return n
        n += b

def pdftokenizer(args, fh):
    """
    pdftokenizer splits a pdf in tokens, which are then parsed into higher level objects by parsepdf
    """
    while True:
        b = fh.read(1)

        if b == b'':
            break
        if is_whitespace(b):
            pass
        elif b == b'%':
            cmtdata = parse_comment(fh)
            yield PdfComment(cmtdata)
        elif b == b'(':
            strdata = parse_string(fh)
            yield PdfString(strdata)
        elif b == b'<':
            b = fh.read(1)
            if b==b'<':
                yield PdfNesting(b"<<")
            elif b==b'>':
                yield PdfHexdata(b'')
            elif b:
                hexdata = parse_hexdata(fh)
                yield PdfHexdata(b + hexdata)
        elif b == b'>':
            b = fh.read(1)
            if b==b'>':
                yield PdfNesting(b">>")
            else:
                raise Exception("unexpected > at 0x%x" % fh.tell())
        elif b == b'[':
            yield PdfNesting(b"[")
        elif b == b']':
            yield PdfNesting(b"]")
        elif b == b'/':
            name = parse_name(args, fh)
            yield PdfName(name)
        elif b in b"-.0123456789":
            num = parse_number(fh)
            yield PdfNumber(b + num)
        else:
            token = parse_name(args, fh)
            # false, true, null, R, obj, endobj, stream, endstream, startxref, xref, trailer
            yield PdfOperator(b + token)

def readuntil(fh, tag):
    """
    Reads from the filestream until the tag is found.
    Leaves tag in the stream.
    """
    data = b''
    curpos = 0
    while True:
        block = fh.read(1024)
        if block == b'':
            break
        data += block
        ix = data.find(tag, curpos)
        if ix>=0:
            fh.unget(data[ix:])
            return data[:ix], True
        curpos = len(data)-len(tag)
    return data, False

def eolpos(data, pos):
    ixl = []
    for c in b"\r\n":
        ix = data.find(c, pos)
        if ix>=0:
            ixl.append(ix)
    return min(ixl) if ixl else -1

def readuntileol(fh):
    """
    Reads from the filestream until CR, CRLF or LF is encoutered
    """
    data = b''
    curpos = 0
    while True:
        block = fh.read(1024)
        if block == b'':
            break
        data += block
        ix = eolpos(data, curpos)
        if ix>=0:
            fh.unget(data[ix:])
            return data[:ix]
        curpos = len(data)
    return data



def skipws(fh):
    while True:
        b = fh.read(1)
        if b == b'':
            return
        if b not in b'\r\n':
            fh.unget(b)
            return


def parsepdf(args, fh):
    """
    parsepdf reads the stream, creates tokens, and from extracts nested structures
    like dicts, arrays, objects and streams

    returns the remaining stack + the list of objects.

    todo: return trailer and xref as seperate objects.
    """
    objects = dict()
    stack = []
    def searchstack(itm1):
        for i, itm0 in enumerate(stack[::-1]):
            if isinstance(itm0, PdfNesting) and itm1.closes(itm0):
                return -i
        if args.danglingfatal:
            raise Exception("could not find opening item for %s at 0x%x" % (itm1, fh.tell()))
        else:
            if args.verbose:
                print("could not find opening item for %s at 0x%x" % (itm1, fh.tell()))
            return None

    def getobjref():
        objgen = stack.pop()
        if not isinstance(objgen, PdfNumber): raise Exception("expected number")
        objid = stack.pop()
        if not isinstance(objid, PdfNumber): raise Exception("expected number")
        return objid.asint(), objgen.asint()


    start, found = readuntil(fh, b'%PDF')
    if not found:
        raise Exception("No %PDF tag found")

    # todo: some pdfs have non-comment garbage on the 2nd line

    if args.verbose:
        print("skipping: %s" % start)
    for item in pdftokenizer(args, fh):
        if args.verbose:
            print(item)
        if isinstance(item, PdfComment):
            if item.value.startswith(b'%EOF'):
                nextbytes = fh.read(16)
                # some site have broken download methods
                if nextbytes.find(b"<!DOCTYPE")>=0:
                    stack.append(item)
                    break
                fh.unget(nextbytes)
            if item.value.startswith(b'PDF'):
                nextbytes = fh.read(4)
                if nextbytes in (b'\xc8\xd2\xf0\xfe', b'\x7a\x47\x5f\xd5', b'\x0a\xc8\xd2\xf0', b'\x0a\x7a\x47\x5f'):
                    nextbytes += readuntileol(fh)
                    print("skipping garbageline: %s" % (binascii.b2a_hex(nextbytes)))
                    continue
                fh.unget(nextbytes)

        if isinstance(item, PdfOperator) and item.value in (b'obj', b'endobj'):
            item = PdfNesting(item.value)
        if isinstance(item, PdfNesting):
            if item.isclose():
                i = searchstack(item)
                if i is None:
                    # buggy pdf - parse anyway
                    stack.append(item)
                else:
                    items = stack[i:] if i<0 else []
                    del stack[i-1:]
                    if item.value==b'>>':
                        stack.append(PdfDictionary(items))
                    elif item.value==b']':
                        stack.append(PdfArray(items))
                    elif item.value==b'endobj':
                        objid, objgen = getobjref()
                        # note: ignoring objgen
                        objects[objid] = PdfObject(items)
                    else:
                        raise Exception("unexpected nest: %s at 0x%x" % (item, fh.tell()))
            else:
                stack.append(item)
        elif isinstance(item, PdfOperator):
            if item.value == b'stream':
                d = stack.pop()
                if not isinstance(d, PdfDictionary): raise Exception("expected dict before stream")
                #if not d.has(b'Length'): raise Exception("expected Length in stream dict")
                skipws(fh)
                strdata, found = readuntil(fh, b'endstream')
                if not found:
                    raise Exception("No endstream found")
                
                stack.append(PdfStream(d, strdata))
            elif item.value == b'R':
                objid, objgen = getobjref()
                stack.append(PdfReference(objid, objgen))
            else:
                stack.append(item)

        else:
            stack.append(item)
    return stack, objects


class UngetStream:
    def __init__(self, fh):
        self.fh = fh
        self.buffer = b''
    def unget(self, data):
        self.buffer = data + self.buffer
    def read(self, size):
        data = b''
        if self.buffer:
            want = min(len(self.buffer), size)
            data, self.buffer = self.buffer[:want], self.buffer[want:]
            size -= want
        if size:
            data += self.fh.read(size)
        return data
    def tell(self):
        return self.fh.tell() - len(self.buffer)


def processfile(args, fh):
    stack, objects = parsepdf(args, UngetStream(fh))
    print(stack)
    for k,v in objects.items():
        print("%05d: %s" % (k, v))
        if args.verbose and isinstance(v.body[0], PdfStream):
            v.body[0].contents()


def DirEnumerator(args, path):
    """
    Enumerate all files / links in a directory,
    optionally recursing into subdirectories,
    or ignoring links.
    """
    for d in os.scandir(path):
        try:
            if d.name == '.' or d.name == '..':
                pass
            elif d.is_symlink() and args.skiplinks:
                pass
            elif d.is_file():
                yield d.path
            elif d.is_dir() and args.recurse:
                for f in DirEnumerator(args, d.path):
                    yield f
        except Exception as e:
            print("EXCEPTION %s accessing %s/%s" % (e, path, d.name))


def EnumeratePaths(args, paths):
    """
    Enumerate all urls, paths, files from the commandline
    optionally recursing into subdirectories.
    """
    for fn in paths:
        try:
            if os.path.islink(fn) and args.skiplinks:
                pass
            elif os.path.isdir(fn) and args.recurse:
                for f in DirEnumerator(args, fn):
                    yield f
            elif os.path.isfile(fn):
                yield fn
        except Exception as e:
            print("EXCEPTION %s accessing %s" % (e, fn))


if __name__=="__main__":
    import sys
    import argparse
    parser = argparse.ArgumentParser(description='pdfparser')
    parser.add_argument('--verbose', '-v', action='count')
    parser.add_argument('--recurse', '-r', action='store_true', help='recurse into directories')
    parser.add_argument('--skiplinks', '-L', action='store_true', help='skip symbolic links')
    parser.add_argument('--errorfatal', '-E', action='store_true', help='abort on errors')
    parser.add_argument('--danglingfatal', '-d', action='store_true', help='error on dangling endobj, bracket')

    parser.add_argument('FILES', type=str, nargs='*', help='Files')
    args = parser.parse_args()


    if args.FILES:
        for fn in EnumeratePaths(args, args.FILES):
            print("==> %s <==" % fn)
            try:
                with open(fn, "rb") as fh:
                    processfile(args, fh)
            except Exception as e:
                print("ERROR %s" % e)
                if args.errorfatal:
                    raise
    else:
        processfile(args, stdin)
