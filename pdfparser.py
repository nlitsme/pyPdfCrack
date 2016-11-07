"""
Simple pdf parser
"""
from __future__ import print_function
import binascii
import struct
import re
import sys
if sys.version_info < (3, 0):
    bytes = bytearray
    reload(sys)
    sys.setdefaultencoding('utf-8')

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


class PdfNesting:
    """ represent a nesting token in the pdf token stream """
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "PdfNesting: %s" % string_nesting_escape(self.value)

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

class PdfName:
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "PdfName: %s" % string_nesting_escape(self.value)

class PdfNumber:
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "PdfNumber: %s" % self.value
    def asint(self):
        return int(self.value)

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

    def get(self, n):
        retnext = False
        for i in self.value:
            if retnext:
                return i
            if isinstance(i, PdfName) and i.value==n:
                retnext = True

class PdfArray:
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "PdfArray: %s" % self.value

class PdfStream:
    def __init__(self, params, data):
        self.data = data
        self.params = params
    def __repr__(self):
        return "PdfStream: %s" % self.params

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
    if b==b'r': return None, b'\r'
    if b==b'n': return None, b'\n'
    if b==b't': return None, b'\t'
    if b==b'b': return None, b'\b'
    if b==b'f': return None, b'\f'
    if b==b'\n': return None, b''
    if b==b'\r': return None, b''
    if b in b'01234567':
        digits = b''
        while len(digits)<3 and b in b"01234567":
            digits += b
            b = fh.read(1)
        return b, struct.pack("B", int(digits, 8))

    # \\, (, ),   and others
    return None, b


def parse_string(fh):
    """ read bracketed and escaped (string) from the pdf """
    res = b''
    plevel = 1
    nextb = None
    while plevel:
        if nextb is None:
            b = fh.read(1)
        else:
            b, nextb = nextb, None

        if b==b'':
            raise Exception("truncated string at EOF")

        if b==b'(':
            plevel += 1
        elif b==b')':
            plevel -= 1
            if plevel==0:
                break
        elif b==b'\\':
            nextb, b = parse_string_escape(fh)
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

def parse_name(fh):
    """ read name-like text from the pdf """
    n = b''
    while True:
        b = fh.read(1)
        if b==b'':
            return None, n
        if b==b'#':
            b = struct.pack("B", int(fh.read(2), 16))
        elif is_whitespace(b):
            return None, n
        elif is_delimiter(b):
            return b, n
        n += b

def parse_number(fh):
    """ read number-like text from the pdf """
    n = b''
    while True:
        b = fh.read(1)
        if b not in b"-.0123456789":
            return b, n
        n += b

def pdftokenizer(fh):
    """
    pdftokenizer splits a pdf in tokens, which are then parsed into higher level objects by parsepdf
    """
    nextb = None
    while True:
        if nextb is None:
            b = fh.read(1)
        else:
            b, nextb = nextb, None

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
            nextb, name = parse_name(fh)
            yield PdfName(name)
        elif b in b"-.0123456789":
            nextb, num = parse_number(fh)
            yield PdfNumber(b + num)
        else:
            nextb, token = parse_name(fh)
            # false, true, null, R, obj, endobj, stream, endstream, startxref, xref, trailer
            yield PdfOperator(b + token)

def readstream(fh):
    """ reads from the pdf until the string 'endstream' is found. """
    strdata = b''
    while True:
        byte = fh.read(1)
        if byte == b'':
            break
        strdata += byte
        if strdata.endswith(b"endstream"):
            break
    return strdata


def parsepdf(fh):
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
        raise Exception("could not find opening item for %s at 0x%x" % (itm1, fh.tell()))
    def getobjref():
        objgen = stack.pop()
        if not isinstance(objgen, PdfNumber): raise Exception("expected number")
        objid = stack.pop()
        if not isinstance(objid, PdfNumber): raise Exception("expected number")
        return objid.asint(), objgen.asint()


    for item in pdftokenizer(fh):
        if isinstance(item, PdfComment) and item.value.startswith(b'%EOF'):
            break
        if isinstance(item, PdfOperator) and item.value in (b'obj', b'endobj'):
            item = PdfNesting(item.value)
        if isinstance(item, PdfNesting):
            if item.isclose():
                i = searchstack(item)
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
                strdata = readstream(fh)
                
                stack.append(PdfStream(d, strdata))
            elif item.value == b'R':
                objid, objgen = getobjref()
                stack.append(PdfReference(objid, objgen))
            else:
                stack.append(item)

        else:
            stack.append(item)
    return stack, objects

if __name__=="__main__":
    import sys
    for fn in sys.argv[1:]:
        print("==> %s <==" % fn)
        try:
            with open(fn, "rb") as fh:
                stack, objects = parsepdf(fh)
                print(stack)
                for k,v in objects.items():
                    print("%05d: %s" % (k, v))
        except Exception as e:
            print("ERROR %s" % e)
            raise
