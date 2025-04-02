from dataclasses import dataclass
import sys
import struct
import ELF
"""
Tool for investigating qualcomm clade compression

Author: Willem Hengeveld <itsme@xs4all.nl>
"""

def MASK(n):
    return (1<<n)-1

def decodewords(data):
    """ generate 32bit integeres from a byte list """
    o = 0
    while o+0x20<=len(data):
        yield from struct.unpack_from("<8L", data, o)
        o += 0x20
    if remaining := len(data)-o:
        yield from struct.unpack_from(f"<{remaining//4}L", data, o)

def intlist2bytes(ilist):
    return struct.pack("<%dL" % len(ilist), *ilist)


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


class CladeDecompressor:
    missingbits = [
        [1, 15],                                                  # 00 + dict1-idx + 2-bits
        [1, 2, 4, 5, 6, 7, 8, 9, 16],                             # 01 + dict2-idx + 9-bits
        [0, 1, 2, 4, 5, 7, 8, 9, 10, 15, 16, 17, 18, 19, 20],     # 10 + dict3-idx + 15-bits
                                                                  # 11 + 32-bits         literal
    ]

    def __init__(self, dicts):
        self.dicts = dicts

    def reconstructword(self, dictword, bitpositions, codebits):
        """
        interleave the bits from dictword with those from codebits
        """
        for i, bitnr in enumerate(bitpositions):
            # w=76543210
            # bitnr=1 -> mask = 0b1
            # h = 7654321--
            # b = -------b-
            # l = --------0

            h = (dictword & ~MASK(bitnr)) << 1
            bit = (codebits & 1) << bitnr
            l = dictword & MASK(bitnr)
            dictword = h | bit | l
            codebits >>= 1
        return dictword

    def decompress(self, compressed):
        bits = BitStreamReader(compressed)
        out = []

        # clade seems to skip the first bit
        first = bits.get(1)
        print(f"firstbit = {first}")

        while True:
            try:
                code = bits.get(2)
                if code < 3:
                    idx = bits.get(11)
                    missing = bits.get(len(self.missingbits[code]))
                    dictword = self.dicts[code][idx]
                    dlen = (len(self.missingbits[code])+3)//4
                    mbtxt = f"{missing:0{dlen}x}"
                    result = self.reconstructword(dictword, self.missingbits[code], missing)
                    print(f"dict{code} {idx:03x}={dictword:08x} {mbtxt:>4} -> {result:08x}")
                else: # literal
                    result = bits.get(32)
                    print(f"literal                 -> {result:08x}")
                out.append(result)
            except EOFError:
                break

        return out

class CladeSegment:
    """
    decodes the structure of the clade segment,

    ending with three 0x2000 byte dictionaries.

    rest currently unknown.
    """
    def __init__(self, fh, args):
        self.fh = fh
        self.baseoffset = fh.tell()
        fh.seek(fh.seek(0,2)&~0x1fff-0x6000)
        dictdata = fh.read(0x6000)
        self.dicts = [list(decodewords(dictdata[_*0x2000:(_+1)*0x2000])) for _ in range(3)]

        from functools import reduce
        for i, d in enumerate(self.dicts):
            print(f"dict{i}: {reduce(lambda a,b:a|b, d):08x}")

    def readchunk(self, i):
        """
        TODO
        don't know yet how chunks are encoded in the clade section.

        there seem to be large blocks, then a section of 64-byte blocks,
        then 32-byte blocks, with ever smaller n-byte sized blocks.
        ending with single byte blocks.

        unsure if that is correct. but byte patterns suggest this.
        """
        self.fh.seek(self.baseoffset)
        return self.fh.read(0x2000)

def processfile(fh, args):
    """
    decodes the clade section at the current file position
    """
    cl = CladeSegment(fh, args)

    if args.output:
        ofh = open(args.output, "wb")
    elif not args.nooutput:
        import sys
        ofh = sys.stdout.buffer
    else:
        ofh = None

    C = CladeDecompressor(cl.dicts)
    C.debug = args.debug

    cdata = cl.readchunk(0)
    cdata = list(decodewords(cdata))

    if args.debug:
        print(f"[{i:04x}] {ofs:08x}-{ofs+size:08x}")

    uncomp = C.decompress(cdata)
    udata = words2bytes(uncomp)

    if ofh:
        ofh.flush()
        ofh.write(udata)


def processhex(hexstr, args):
    """
    decompress clade bytes specified on the commandline,
    while reading the dicts from the dictfile.
    """
    data = bytes.fromhex(hexstr)

    with open(args.dictfile, "rb") as fh:
        cl = CladeSegment(fh, args)

    C = CladeDecompressor(cl.dicts)
    C.debug = args.debug

    uncomp = C.decompress(list(decodewords(data)))
    udata = intlist2bytes(uncomp)

    print(udata.hex())

class ElfReader:
    """
    wrapper translating ELF virtual addresses to file reads.
    """
    def __init__(self, fh):
        import ELF
        self.elf = ELF.read(fh)
        self.fh = fh

        # fh.seek(elf.virt2file(baseofs))
        # dataend = elf.virtend(baseofs)
        # fh.seek(elf.virt2file(ofs))
        # fh.seek(elf.virt2file(ofs))
    def tell(self):
        return self.elf.file2virt(self.fh.tell())
    def seek(self, ofs, whence=0):
        if whence == 0:
            r = self.fh.seek(self.elf.virt2file(ofs))
        elif whence == 1:
            r = self.fh.seek(ofs, 1)
        elif whence == 2:
            r = self.fh.seek(ofs, 2)
        return self.elf.file2virt(r)

    def read(self, size=None):
        return self.fh.read(size)


def main():
    import argparse
    class Int(argparse.Action):
        """ argparse action to convert 0xNNN ints to integers """
        def __call__(self, parser, namespace, values, option_string=None):
            setattr(namespace, self.dest, int(values, 0))

    parser = argparse.ArgumentParser(description='Decompress packed clade ELF sections')
    parser.add_argument('--offset', '-o', help='Which clade section to decompress', type=str, default="0")
    parser.add_argument('--length', '-l', help='size of section (rawfile only)', type=str)
    parser.add_argument('--dump', help='hex dump of compressed data', action='store_true')
    parser.add_argument('--verbose', '-v', action='count')
    parser.add_argument('--debug', action='store_true', help="show all compression opcodes")
    parser.add_argument('--nooutput', '-n', action='store_true', help="don't output decompressed data")
    parser.add_argument('--output', type=str, help='Save output to file')
    parser.add_argument('--dictfile', '-D', help='(for --hex) load dict from file', type=str)
    parser.add_argument('--baseoffset', '-O', help='(ELF) offset to the clade segment', action=Int, default=0)
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
            elfmagic = fh.read(4)
            if elfmagic == b"\x7fELF":
                fh.seek(0)
                fh = ElfReader(fh)

            fh.seek(args.baseoffset)
            processfile(fh, args)
    else:
        print("no inpput specified: either --hex or elffile")

if __name__=="__main__":
    main()

