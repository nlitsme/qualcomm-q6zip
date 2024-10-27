"""
Tool for decompressing q6zip compressed CODE sections.

Author: Willem Hengeveld <itsme@gsmk.de>
"""
# from https://github.com/EchoQian/PhoebeM/blob/master/modem_proc/core/kernel/dlpager/src/dlpager_q6zip.c
#   dlpager_load_virtual_page_rx calls q6zip_uncompress
#   dlpager_load_virtual_page decides to call ..._rx
# https://github.com/EchoQian/PhoebeM/blob/master/modem_proc/core/kernel/dlpager/src/q6zip_uncompress.c
# https://github.com/EchoQian/PhoebeM/blob/master/modem_proc/core/kernel/dlpager/compressor/compress_process.py
from __future__ import division, print_function
from dataclasses import dataclass
import sys
import struct
import argparse

import ELF

if sys.version_info < (3, 0):
    stdout = sys.stdout
else:
    stdout = sys.stdout.buffer


def MASK(n):
    return (1<<n)-1

def bitlog(n):
    # note: in python3   bitlog(n) == n.bit_length-1
    # 2**(x.bit_length-1) <= x < 2**x.bit_length
    # 2**bitlog(x) <= x < 2 * 2**bitlog(x)
    r = -1
    while n:
        n >>= 1
        r += 1
    return r


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



class Q6Unzipper:
    """
    Decompresses data encoded using the following bit packed format:

    The data is packed with a variable length opcode, listed in the table below.
    Read the opcodes from right-to-left.

               <entry1:10>      100   |13|  DICT1_MATCH       dict1 nnn                out.addword(self.dict1[entry])
               <entry2:12>     0101   |16|  DICT2_MATCH       dict1 nnnn               out.addword(self.dict2[entry])
               <lastout:9>      001   |12|  MATCH_8N_SQ0      lookback  lb=nnn         out.copyword(lastOut)
                                111   | 3|  MATCH_8N_SQ1      seq                      out.copyword(lastOut)
               <dword:32>       011   |35|  NO_MATCH          lit nnnnnnnn             out.addword(masked)
                                                                                       
   <masked:8>               0011010   |15|  MATCH_6N_2x4_SQ1  mask @16 m:nn            out.copybits(lastOut, masked, 8, 16)   or END_BLOCK
   <masked:8>               1011010   |15|  MATCH_6N_2x2_SQ1  mask @8 m:nn             out.copybits(lastOut, masked, 8, 8)
   <masked:8>                   110   |11|  MATCH_6N_2x0_SQ1  mask @0 m:nn             out.copybits(lastOut, masked, 8, 0)
   <masked:12>                11101   |17|  MATCH_5N_3x0_SQ1  mask @0 m:nnn            out.copybits(lastOut, masked, 12, 0)
   <masked:16>               001010   |22|  MATCH_4N_4x0_SQ1  mask @0 m:nnnn           out.copybits(lastOut, masked, 16, 0)

   <masked:8>  <lastout:9>   101010   |23|  MATCH_6N_2x4_SQ0  mask @16 m:nn  lb=nnn    out.copybits(lastOut, masked, 8, 16)
   <masked:8>  <lastout:9>   111010   |23|  MATCH_6N_2x2_SQ0  mask @8 m:nn  lb=nnn     out.copybits(lastOut, masked, 8, 8)
   <masked:8>  <lastout:9>      000   |20|  MATCH_6N_2x0_SQ0  mask @0 m:nn  lb=nnn     out.copybits(lastOut, masked, 8, 0)
   <masked:12> <lastout:9>     0010   |25|  MATCH_5N_3x0_SQ0  mask @0 m:nnn  lb=nnn    out.copybits(lastOut, masked, 12, 0)
   <masked:16> <lastout:9>    01101   |30|  MATCH_4N_4x0_SQ0  mask @0 m:nnnn  lb=nnn   out.copybits(lastOut, masked, 16, 0)

    """
    def __init__(self, dict1, dict2, lookback=8):
        self.debug = False

        self.dict1 = dict1
        self.dict2 = dict2

        self.LB_BITS = lookback

        self.DICT1_BITS = bitlog(len(dict1))
        self.DICT2_BITS = bitlog(len(dict2))

    def decompress(self, compressed, MAXOUT=0x400):
        """
        Decompresses data from a byte array `compressed`, returning the uncompressed data bytes.
        """
        bits = BitStreamReader(compressed)
        out = WordStreamWriter()

        lastOut = -1        #  this is the only state of the algorithm.

        if self.debug:
            def log(msg):
                print("    [%4x] %4x:%2d  %08x (%3d) %s" % (out.len(), bits.pos, bits.bitpos, out.data[-1] if out.data else 0, lastOut, msg))

            print("    outofs  ofs:bit  outdata last action")
        else:
            def log(msg):
                pass

        try:
            while out.len() <= MAXOUT:
                op1 = bits.get(3)
                if op1 == 0:  # MATCH_6N_2x0_SQ0 set lastout, byte from stream
                    lastOut = bits.get(self.LB_BITS) - (1<<self.LB_BITS)
                    masked = bits.get(8)
                    out.copybits(lastOut, masked, 8, 0)
                    log(f"mask @0 m:{masked:02x}  lb={lastOut+2**self.LB_BITS:03x}")
                elif op1 == 1:  # MATCH_8N_SQ0 set lastout, dword from lastout
                    lastOut = bits.get(self.LB_BITS) - (1<<self.LB_BITS)
                    out.copyword(lastOut)

                    log(f"lookback  lb={lastOut+2**self.LB_BITS:03x}")
                elif op1 == 2:
                    if bits.get(1)==0: # MATCH_5N_3x0_SQ0        -- setting lastOut
                        lastOut = bits.get(self.LB_BITS) - (1<<self.LB_BITS)
                        masked = bits.get(12)
                        out.copybits(lastOut, masked, 12, 0)
                        log(f"mask @0 m:{masked:03x}  lb={lastOut+2**self.LB_BITS:03x}")
                    else:
                        op2 = bits.get(2)
                        if op2==0: # MATCH_4N_4x0_SQ1   -- reusing 'lastOut'
                            masked = bits.get(16)
                            out.copybits(lastOut, masked, 16, 0)
                            log(f"mask @0 m:{masked:04x}")
                        elif op2==2: # MATCH_6N_2x4_SQ0        -- setting lastOut
                            lastOut = bits.get(self.LB_BITS) - (1<<self.LB_BITS)
                            masked = bits.get(8)
                            out.copybits(lastOut, masked, 8, 16)
                            log(f"mask @16 m:{masked:02x}  lb={lastOut+2**self.LB_BITS:03x}")
                        elif op2==3: # MATCH_6N_2x2_SQ0        -- setting lastOut
                            lastOut = bits.get(self.LB_BITS) - (1<<self.LB_BITS)
                            masked = bits.get(8)
                            out.copybits(lastOut, masked, 8, 8)
                            log(f"mask @8 m:{masked:02x}  lb={lastOut+2**self.LB_BITS:03x}")
                        elif bits.get(1): # MATCH_6N_2x2_SQ1   -- reusing 'lastOut'
                            masked = bits.get(8)
                            out.copybits(lastOut, masked, 8, 8)
                            log(f"mask @8 m:{masked:02x}")
                        else: # MATCH_6N_2x4_SQ1    -- reusing 'lastOut'
                            masked = bits.get(8)
                            if masked != 0xFF:
                                # .. in the modem.elf binary a check is here for masked==0xff -> stop
                                out.copybits(lastOut, masked, 8, 16)
                                log(f"mask @16 m:{masked:02x}")
                            else:
                                log("break")
                                if out.len() >= MAXOUT:
                                    break
                elif op1 == 3: # NO_MATCH
                    masked = bits.get(32)
                    out.addword(masked)
                    log(f"lit {masked:08x}")
                elif op1 == 4: # DICT1_MATCH
                    entry = bits.get(self.DICT1_BITS)
                    out.addword(self.dict1[entry])
                    log(f"dict1 {entry:03x}")
                elif op1 == 5:
                    if bits.get(1)==0: # DICT2_MATCH
                        entry = bits.get(self.DICT2_BITS)
                        out.addword(self.dict2[entry])
                        log(f"dict2 {entry:04x}")
                    else:
                        if bits.get(1): # MATCH_5N_3x0_SQ1   -- reusing 'lastOut'
                            masked = bits.get(12)
                            out.copybits(lastOut, masked, 12, 0)
                            log(f"mask @0 m:{masked:03x}")
                        else: # MATCH_4N_4x0_SQ0        -- setting lastOut
                            lastOut = bits.get(self.LB_BITS) - (1<<self.LB_BITS)
                            masked = bits.get(16)
                            out.copybits(lastOut, masked, 16, 0)
                            log(f"mask @0 m:{masked:04x}  lb={lastOut+2**self.LB_BITS:03x}")
                elif op1 == 6:   # MATCH_6N_2x0_SQ1 byte from stream   -- reusing 'lastOut'
                    masked = bits.get(8)
                    out.copybits(lastOut, masked, 8, 0)
                    log(f"mask @0 m:{masked:02x}")
                elif op1 == 7:   # MATCH_8N_SQ1  dword from lastout   -- reusing 'lastOut'
                    out.copyword(lastOut)
                    log("seq")
                else:
                    print("unexpected op", op1)

        except EOFError:
            log("EOF")
        finally:
            log("done")

        return out.data


def bytes2intlist(data):
    if len(data) % 4:
        print("WARNING: unaligned data: %s" % data.hex())
    return list(struct.unpack("<%dL" % (len(data)//4), data))

def intlist2bytes(ilist):
    return struct.pack("<%dL" % len(ilist), *ilist)

def splitdictsize(size):
    bits = []
    mask = 1
    while size and mask < 0x10000000:
        if size&mask:
            bits.append(mask)
            size &= ~mask
        mask <<= 1
    return bits

def splitbits(value, *bitfields):
    """ return bitfields in lsb->msb order """
    l = []
    for n in bitfields:
        field = value & MASK(n)

        value >>= n

        l.append(field)
    return tuple(l)

def signed(value, bits):
    if value > 2**(bits-1):
        return value - 2**bits
    return value

def getchunkmeta(value):
    @dataclass
    class Meta:
        lastseq : int   # signed
        bitsleft : int
        indelta : int
        outdelta : int  # signed

        def __repr__(self):
            return f"{self.lastseq:>4x},{self.bitsleft:>2x},{self.indelta:>3x},{self.outdelta:>3x}"

    bits = splitbits(value, 10, 6, 10, 6)

    return Meta(signed(bits[0], 10), bits[1], bits[2], signed(bits[3], 6))


def processrawfile(fh, args):
    """
    decompresses a .elf section saved to a separate file,
    like how the modem.bNN files are stored in the NON-HLOS filesystem

    with --offset you can specify a specific block to decode.
    """
    npages, version = struct.unpack("<HH", fh.read(4))

    dict1size, dict2size = splitdictsize(args.dictsize)
    dict1 = bytes2intlist(fh.read(dict1size*4))
    dict2 = bytes2intlist(fh.read(dict2size*4))

    ptrs = bytes2intlist(fh.read(npages*4))

    firstblk_ofs = fh.tell()

    fh.seek(0, 2)
    dataend_ofs = fh.tell()
    dataend_ptr = dataend_ofs - firstblk_ofs + ptrs[0]

    sizes = [ b-a for a, b in zip(ptrs, ptrs[1:] + [ dataend_ptr ] ) ]

    offsets = []
    o = firstblk_ofs
    for s in sizes:
        offsets.append(o)
        o += s
    offsets.append(dataend_ofs)

    if args.verbose:
        print("p0 = %08x,  datastart=%08x, filepos=%08x" % (ptrs[0], firstblk_ofs, fh.tell()))

    if args.dump:
        print("%08x: npages=%d, ver=0x%04x" % (0, npages, version))
        print("%08x: dict1 - %d words" % (4, dict1size))
        print("%08x: dict2 - %d words" % (4+4*dict1size, dict2size))
        print("%08x: ptrlist" % (4+4*dict1size+4*dict2size))
        print("%08x: compressed data" % (4+4*dict1size+4*dict2size+4*npages))
        for i, (ofs, size) in enumerate(zip(offsets, sizes)):
            if args.offset and args.offset!=ofs:
                continue
            fh.seek(ofs)
            cdata = fh.read(size)

            cdata = bytes2intlist(cdata)

            if i < args.skipheader:
                a0 = getchunkmeta(cdata[0])
                # (-1, 1..32, 0..4, 1..4)
                a1 = getchunkmeta(cdata[1])
                # (-1, 1..32, *, -4..2)

                cdata = cdata[2:]

                print("%08x: [%04x] (%s) (%s) (l=%03x) %s" % (ofs, i, a0, a1, len(cdata), " ".join("%08x" % _ for _ in cdata)))
            else:
                print("%08x: [%04x] %s" % (ofs, i, " ".join("%08x" % _ for _ in cdata)))

    else:
        if args.output:
            ofh = open(args.output, "wb")
        elif not args.nooutput:
            ofh = stdout
        else:
            ofh = None

        C = Q6Unzipper(dict1, dict2, args.lookback)
        C.debug = args.debug

        for i, (ofs, size) in enumerate(zip(offsets, sizes)):
            if args.offset and args.offset!=ofs:
                continue
            fh.seek(ofs)
            cdata = fh.read(size)

            if i < args.skipheader:
                if args.verbose:
                    print(f"skipheader: {cdata[:8].hex()}")
                cdata = cdata[8:]

            uncomp = C.decompress(bytes2intlist(cdata), args.maxout)
            udata = intlist2bytes(uncomp)

            if args.verbose:
                print("%08x: %04x -> %04x" % (ofs, size, len(udata)))
                if args.verbose>1:
                    print("        : %s" % cdata.hex())
                    print("        : %s" % udata.hex())
            if ofh:
                ofh.flush()
                ofh.write(udata)


def processhex(hexstr, args):
    data = bytes.fromhex(hexstr)

    with open(args.dictfile, "rb") as fh:
        fh.seek(4)
        dict1size, dict2size = splitdictsize(args.dictsize)
        dict1 = bytes2intlist(fh.read(dict1size*4))
        dict2 = bytes2intlist(fh.read(dict2size*4))

    C = Q6Unzipper(dict1, dict2, args.lookback)
    C.debug = args.debug

    uncomp = C.decompress(bytes2intlist(data), args.maxout)
    udata = intlist2bytes(uncomp)

    print(udata.hex())


def processelffile(fh, args):
    baseofs = args.dictoffset
    elf = ELF.read(fh)

    fh.seek(elf.virt2file(baseofs))

    npages, version = struct.unpack("<HH", fh.read(4))

    dict1size, dict2size = splitdictsize(args.dictsize)
    dict1 = bytes2intlist(fh.read(dict1size*4))
    dict2 = bytes2intlist(fh.read(dict2size*4))

    ptrs = bytes2intlist(fh.read(npages*4))
    datastart = baseofs + 4 + args.dictsize*4 + npages*4
    dataend = elf.virtend(baseofs)

    if args.verbose:
        print("p0 = %08x,  datastart=%08x, filepos=%08x" % (ptrs[0], datastart, fh.tell()))

    if args.dump:
        print("%08x: npages=%d, ver=0x%04x" % (baseofs, npages, version))
        print("%08x: dict1 - %d words" % (baseofs+4, dict1size))
        print("%08x: dict2 - %d words" % (baseofs+4+4*dict1size, dict2size))
        print("%08x: ptrlist" % (baseofs+4+4*dict1size+4*dict2size))
        print("%08x: compressed data" % (baseofs+4+4*dict1size+4*dict2size+4*npages))
        for i, (ofs, nextofs) in enumerate(zip(ptrs, ptrs[1:]+[dataend])):
            if args.offset and args.offset!=ofs:
                continue
            fh.seek(elf.virt2file(ofs))
            cdata = fh.read(nextofs-ofs)

            cdata = bytes2intlist(cdata)

            if i < args.skipheader:
                a0 = getchunkmeta(cdata[0])
                # (-1, 1..32, 0..4, 1..4)
                a1 = getchunkmeta(cdata[1])
                # (-1, 1..32, *, -4..2)

                cdata = cdata[2:]

                print("%08x: [%04x] (%s) (%s) (l=%03x) %s" % (ofs, i, a0, a1, len(cdata), " ".join("%08x" % _ for _ in cdata)))
            else:
                print("%08x: [%04x] %s" % (ofs, i, " ".join("%08x" % _ for _ in cdata)))

    else:
        if args.output:
            ofh = open(args.output, "wb")
        elif not args.nooutput:
            ofh = stdout
        else:
            ofh = None

        C = Q6Unzipper(dict1, dict2, args.lookback)
        C.debug = args.debug

        for i, (ofs, nextofs) in enumerate(zip(ptrs, ptrs[1:]+[dataend])):
            if args.offset and args.offset!=ofs:
                continue
            fh.seek(elf.virt2file(ofs))
            cdata = fh.read(nextofs-ofs)

            if i < args.skipheader:
                if args.verbose:
                    print(f"skipheader: {cdata[:8].hex()}")
                cdata = cdata[8:]

            uncomp = C.decompress(bytes2intlist(cdata), args.maxout)
            udata = intlist2bytes(uncomp)

            if args.verbose:
                print("%08x: %04x -> %04x" % (ofs, nextofs-ofs, len(udata)))
                if args.verbose>1:
                    print("        : %s" % cdata.hex())
                    print("        : %s" % udata.hex())
            if ofh:
                ofh.flush()
                ofh.write(udata)


def decompresssingle(fh, args):
    """
    decompress a single block
    note: args.offset has a different meaning for this function
    """
    def getdict(spec):
        a, b = spec.split(':')
        return int(a, 0), int(b, 0)

    elf = ELF.read(fh)

    dict1ofs, dict1size = getdict(args.dict1)
    dict2ofs, dict2size = getdict(args.dict2)

    fh.seek(elf.virt2file(dict1ofs))
    dict1 = bytes2intlist(fh.read(dict1size*4))

    fh.seek(elf.virt2file(dict2ofs))
    dict2 = bytes2intlist(fh.read(dict2size*4))

    C = Q6Unzipper(dict1, dict2, args.lookback)
    C.debug = args.debug

    fh.seek(elf.virt2file(args.offset))
    cdata = fh.read(args.size)

    uncomp = C.decompress(bytes2intlist(cdata), args.maxout)
    udata = intlist2bytes(uncomp)

    print("comp    : %s" % cdata.hex())
    print("full    : %s" % udata.hex())


def main():
    parser = argparse.ArgumentParser(description='Decompress packed q6zip ELF sections')
    parser.add_argument('--offset', '-o', help='Which q6zip section to decompress', type=str)
    parser.add_argument('--size', '-s', help='how many bytes to decompress', type=str)
    parser.add_argument('--dump', help='hex dump of compressed data', action='store_true')
    parser.add_argument('--verbose', '-v', action='count')
    parser.add_argument('--debug', action='store_true', help="show all compression opcodes")
    parser.add_argument('--rawfile', action='store_true', help="file contains only the q6zip section")
    parser.add_argument('--nooutput', '-n', action='store_true', help="don't output decompressed data")
    parser.add_argument('--output', type=str, help='Save output to file')
    parser.add_argument('--maxout', type=str, help='how much data to decompress', default='0x400')

# TODO: automatically determine dictsize
    parser.add_argument('--dictsize', '-d', help='size of the dictionary in words', type=str, default='0x4400')
    parser.add_argument('--dictfile', '-D', help='load dict from', type=str)
    parser.add_argument('--dictoffset', '-O', help='load dict from', type=str)
    parser.add_argument('--lookback', help='lookback depth', type=str, default='8')
# TODO: automatically determine skipheader
    parser.add_argument('--skipheader', help='number of items with extra skip header', type=str, default='0xf7a') # for quectel

    parser.add_argument('--dict1', help='where is dict1', type=str)
    parser.add_argument('--dict2', help='where is dict2', type=str)
    parser.add_argument('--hex', type=str, help='uncompress hex data')

    parser.add_argument('elffile', help='Which file to process', type=str, nargs='?')
    args = parser.parse_args()

    if args.offset is not None:
        args.offset = int(args.offset, 0)
    if args.size is not None:
        args.size = int(args.size, 0)
    if args.dictsize is not None:
        args.dictsize = int(args.dictsize , 0)
    if args.dictoffset is not None:
        args.dictoffset = int(args.dictoffset , 0)
    if args.lookback is not None:
        args.lookback = int(args.lookback , 0)
    if args.skipheader is not None:
        args.skipheader = int(args.skipheader , 0)

    args.maxout = int(args.maxout, 0)

    if args.hex:
        processhex(args.hex, args)
    elif args.elffile:
        with open(args.elffile, "rb") as fh:
            if args.rawfile:
                processrawfile(fh, args)
            elif args.dict1 and args.dict2:
                decompresssingle(fh, args)
            else:
                processelffile(fh, args)
    else:
        print("no inpput specified: either --hex or elffile")

if __name__=="__main__":
    main()

