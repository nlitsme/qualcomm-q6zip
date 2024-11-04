from dataclasses import dataclass
import sys
import struct
import argparse

import ELF

def MASK(n):
    return (1<<n)-1


class BitStreamReader:
    """
    Get bit chunks from `data`. starting at the LSB.
    """
    def __init__(self, data):
        self.data = data
        self.pos = -1
        self.bitpos = 32
        self.value = None

    def nextvalue(self):
        """
        Loads next `value` from `data`, advancing `pos` and `bitpos`.
        """
        self.pos += 1
        if self.pos >= len(self.data):
            raise EOFError()
        self.value = self.data[self.pos]
        self.bitpos = 0

    def get(self, n):
        """
        Return next `n` bits, crossing word boundaries
        """
        result = 0
        shift = 0

        # loop until all bits obtained.
        while n>0:

            # calculate the maximum number of bits we can get from
            # the current `value`.
            want = min(32-self.bitpos, n)

            result |= self.getsome(want) << shift

            shift += want
            n -= want

        return result

    def getsome(self, n):
        """
        Return the next available chunk of `n` bits.
        """
        if self.bitpos>=32:
            self.nextvalue()

        assert(self.bitpos + n <= 32)

        value = (self.value >> self.bitpos) & MASK(n)
        self.bitpos += n
        return value


class WordStreamWriter:
    """
    Output stream which can duplicate values pushed to it at an earlier time.
    """
    def __init__(self):
        self.data = []

    def len(self):
        return len(self.data)

    def addword(self, value):
        """
        Add a new value.
        """
        self.data.append(value)

    def copyword(self, lastout):
        """
        Copy a dword from the specified earlier position.
        """
        if -lastout>len(self.data):
            self.data.append(0)
        else:
            self.data.append(self.data[lastout])

    def copybits(self, lastout, srcval, bitlen, bitofs):
        """
        Use an earlier value, replacing `bitlen` bits starting at `bitofs`
        with bits from `srcval`.
        """
        if -lastout>len(self.data):
            value = 0
        else:
            value = self.data[lastout] & ~(MASK(bitlen)<<bitofs) 
        value |= (srcval & MASK(bitlen)) << bitofs
        self.data.append(value)

class CladeDecompressor:
    missingbits = [
        [1, 15],                                                  # 00 + dict1-idx + 2-bits
        [1, 2, 4, 5, 6, 7, 8, 9, 16],                             # 01 + dict2-idx + 9-bits
        [0, 1, 2, 4, 5, 7, 8, 9, 10, 15, 16, 17, 18, 19, 20],     # 10 + dict3-idx + 15-bits
                                                                  # 11 + 32-bits         literal
    ]

    def __init__(self, dicts):
        self.dicts = dicts

    def decompress(self, compressed):
        bits = BitStreamReader(compressed)
        out = WordStreamWriter()

        while out.len() < 0x400:
            code = bits.get(2)
            if code < 3:
                idx = bits.get(13)
                missing = bits.get(len(self.missingbits[code]))
                print(f"dict{code} {idx:03x} {missing:04x}")
            else:
                lit = bits.get(32)
                print(f"literal {lit:08x}")


def bytes2intlist(data):
    if len(data) % 4:
        print("WARNING: unaligned data: %s" % (data.hex()))
    return list(struct.unpack("<%dL" % (len(data)/4), data))

def intlist2bytes(ilist):
    return struct.pack("<%dL" % len(ilist), *ilist)

def processhex(hexstr, args):
    data = bytes.fromhex(hexstr)
    C = CladeDecompressor([ [], [], [] ])
    C.debug = args.debug

    uncomp = C.decompress(bytes2intlist(data))
    udata = intlist2bytes(uncomp)

    print(udata.hex())


def main():
    parser = argparse.ArgumentParser(description='Decompress packed clade ELF sections')
    parser.add_argument('--offset', '-o', help='Which clade section to decompress', type=str, default="0")
    parser.add_argument('--length', '-l', help='size of section (rawfile only)', type=str)
    parser.add_argument('--dump', help='hex dump of compressed data', action='store_true')
    parser.add_argument('--verbose', '-v', action='count')
    parser.add_argument('--debug', action='store_true', help="show all compression opcodes")
    parser.add_argument('--rawfile', action='store_true', help="file contains only the clade section")
    parser.add_argument('--nooutput', '-n', action='store_true', help="don't output decompressed data")
    parser.add_argument('--output', type=str, help='Save output to file')
    parser.add_argument('--hex', type=str, help='uncompress hex data')
    parser.add_argument('elffile', help='Which file to process', type=str, nargs='?')
    args = parser.parse_args()

    args.offset = int(args.offset, 0)
    if args.length is not None:
        args.length = int(args.length, 0)

    if args.hex:
        processhex(args.hex, args)
    elif args.elffile:
        with open(args.elffile, "rb") as fh:
            if args.rawfile:
                processrawfile(fh, args)
            else:
                processelffile(fh, args)
    else:
        print("no inpput specified: either --hex or elffile")

if __name__=="__main__":
    main()

