"""
Tool for decompressing delta compressed DATA sections.

Author: Willem Hengeveld <itsme@gsmk.de>
"""
# from https://github.com/EchoQian/PhoebeM/blob/master/modem_proc/core/kernel/dlpager/src/dlpager_q6zip.c
#   dlpager_load_virtual_page_rw  calls deltaUncompress
#   dlpager_load_virtual_page decides to call ..._rw
# https://github.com/EchoQian/PhoebeM/blob/master/modem_proc/core/kernel/dlpager/src/rw_compress.c
# https://github.com/EchoQian/PhoebeM/blob/master/modem_proc/core/kernel/dlpager/compressor/rw_py_compress.py
from __future__ import division, print_function
import sys
import struct
import argparse
from binascii import b2a_hex, a2b_hex

import ELF

if sys.version_info < (3, 0):
    stdout = sys.stdout
else:
    stdout = sys.stdout.buffer


def MASK(n):
    return (1<<n)-1

class DeltaDecompressor:
    """
    Decompresses data encoded using the following bit packed format:

    Each code consists of a 2 bit opcode, followed by one or more bit packed parameters.

       00                   -> val = 0x00000000
       01 aa                -> val = anchors[aa]
       10 aa <10bit delta>  -> val = anchors[aa] = anchors[aa].bits31-10 | delta
       11 <32bits>          -> anchors[i++] = val = 32bits

    note: investigation of 9 differnt sample files shows all use 2 anchor bits, and 10 delta bits.
    """
    def __init__(self, deltabits=10, anchorbits=2):
        self.deltabits = deltabits
        self.anchorbits = anchorbits
        self.debug = False

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

    class BitStreamWriter:
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


    def decompress(self, compressed):
        """
        Decompresses data from a byte array `compressed`, returning the uncompressed data bytes.
        """
        bits = self.BitStreamReader(compressed)
        out = self.BitStreamWriter()

        nanchors = 1<<self.anchorbits
        __anchors = [0] * nanchors
        curanchor = nanchors - 1

        if self.debug:
            def log(msg):
                print("    [%4x] %4x:%2d  %08X %s" % (out.len(), bits.pos, bits.bitpos, out.data[-1] if out.data else 0, msg))
        else:
            def log(msg):
                pass

        try:
            while out.len() < 0x400:
                code = bits.get(2)
                if code == 0:
                    out.addword(0)

                    log("zero")
                elif code == 1:
                    anchor = bits.get(self.anchorbits)
                    out.addword(__anchors[anchor])

                    log("anchor(%d)" % anchor)
                elif code == 2:
                    anchor = bits.get(self.anchorbits)
                    delta = bits.get(self.deltabits)
                    val = __anchors[anchor] = (__anchors[anchor] & ~MASK(self.deltabits)) | delta
                    out.addword(val)

                    log("delta(%d, %03x)" % (anchor, delta))
                elif code == 3:
                    val = bits.get(32)
                    out.addword(val)
                    curanchor = (curanchor + 1) % nanchors
                    __anchors[curanchor] = val 

                    log("save(%08x) -> %d" % (val, curanchor))

        except EOFError:
            log("EOF")
            pass

        return out.data


def bytes2intlist(data):
    if len(data) % 4:
        print("WARNING: unaligned data: %s" % (b2a_hex(data)))
    return struct.unpack("<%dL" % (len(data)/4), data)

def intlist2bytes(ilist):
    return struct.pack("<%dL" % len(ilist), *ilist)

def processhex(hexstr, args):
    data = a2b_hex(hexstr.replace(' ', ''))
    C = DeltaDecompressor(deltabits=args.delta, anchorbits=args.anchor)
    C.debug = args.debug

    uncomp = C.decompress(bytes2intlist(data))
    udata = intlist2bytes(uncomp)

    print(b2a_hex(udata))

def processfile(fh, args):
    """
    Processes the delta compressed section from an ELF binary.
    Depending on the commandline args:

    --dump  - hexdumps the compresseddata and section headers.

    --output  - saves decompressed data to the specified file

    --verbose - prints compressed + uncompressed sizes for each block
    -vv       - hexdumps both compressed and uncompressed data
    
    """
    elf = ELF.read(fh)

    fileofs = elf.virt2file(args.offset)
    if not fileofs:
        print("Could not file the specified offset in the ELF file: %08x" % (args.offset))
        return
    fh.seek(fileofs)

    npages, unknown = struct.unpack("<HH", fh.read(4))

    ptrs = bytes2intlist(fh.read(npages*4))
    datastart = args.offset + 4 + npages*4
    dataend = elf.virtend(args.offset)

    if args.verbose:
        print("file:%08x,  p0 = %08x,  datastart=%08x, filepos=%08x" % (fileofs, ptrs[0], datastart , fh.tell()))

    if args.dump:
        print("%08x: npages=%d, unk=0x%04x" % (args.offset, npages, unknown))
        print("%08x: ptrlist" % (args.offset+4))
        print("%08x: compressed data" % (args.offset+4+4*npages))
        for i, (ofs, nextofs) in enumerate(zip(ptrs, ptrs[1:]+(dataend,))):
            fh.seek(elf.virt2file(ofs))
            cdata = fh.read(nextofs-ofs)

            cdata = bytes2intlist(cdata)

            print("%08x: [%04x] %s" % (ofs, i, " ".join("%08x" % _ for _ in cdata)))

    else:
        if args.output:
            ofh = open(args.output, "wb")
        elif not args.nooutput:
            ofh = stdout
        else:
            ofh = None

        C = DeltaDecompressor(deltabits=args.delta, anchorbits=args.anchor)

        C.debug = args.debug

        for i, (ofs, nextofs) in enumerate(zip(ptrs, ptrs[1:]+(dataend,))):
            fh.seek(elf.virt2file(ofs))
            cdata = fh.read(nextofs-ofs)

            uncomp = C.decompress(bytes2intlist(cdata))
            udata = intlist2bytes(uncomp)

            if args.verbose:
                print("%08x: %04x -> %04x" % (ofs, nextofs-ofs, len(udata)))
                if args.verbose>1:
                    print("        : %s" % b2a_hex(cdata))
                    print("        : %s" % b2a_hex(udata))
            if ofh:
                ofh.flush()
                ofh.write(udata)


def main():
    parser = argparse.ArgumentParser(description='Decompress packed delta ELF sections')
    parser.add_argument('--offset', '-o', help='Which delta section to decompress', type=str)
    parser.add_argument('--dump', help='hex dump of compressed data', action='store_true')
    parser.add_argument('--verbose', '-v', action='count')
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--nooutput', '-n', action='store_true')
    parser.add_argument('--output', type=str, help='Save output to file')
    parser.add_argument('--hex', type=str, help='uncompress hex data')
    parser.add_argument('--delta', type=int, help='number of bits in delta values', default=10)
    parser.add_argument('--anchor', type=int, help='number of bits in anchor values', default=2)
    parser.add_argument('elffile', help='Which file to process', type=str, nargs='?')
    args = parser.parse_args()

    if args.offset is not None:
        args.offset = int(args.offset, 0)

    if args.hex:
        processhex(args.hex, args)
    else:
        with open(args.elffile, "rb") as fh:
            processfile(fh, args)

if __name__=="__main__":
    main()

