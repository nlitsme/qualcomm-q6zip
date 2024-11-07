"""
Tool for decompressing q6zip compressed CODE sections.

Author: Willem Hengeveld <itsme@gsmk.de>
"""
# from https://github.com/EchoQian/PhoebeM/blob/master/modem_proc/core/kernel/dlpager/src/dlpager_q6zip.c
#   dlpager_load_virtual_page_rx calls q6zip_uncompress
#   dlpager_load_virtual_page decides to call ..._rx
# https://github.com/EchoQian/PhoebeM/blob/master/modem_proc/core/kernel/dlpager/src/q6zip_uncompress.c
# https://github.com/EchoQian/PhoebeM/blob/master/modem_proc/core/kernel/dlpager/compressor/compress_process.py

# TODO: add option to decompress a section by ptr index.

from __future__ import division, print_function
from dataclasses import dataclass
import sys
import struct
import argparse

import ELF


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

def bytes2words(data):
    w = []
    o = 0
    while o+4096 <= len(data):
        w.extend(struct.unpack_from("<1024L", data, o))
        o += 4096
    w.extend(struct.unpack_from("<{}L".format((len(data)-o)//4), data, o))
    return w

def words2bytes(w):
    b = bytearray()
    i = 0
    while i+1024 <= len(w):
        b.extend(struct.pack("<1024L", *w[i:i+1024]))
        i += 1024
    b.extend(struct.pack("<{}L".format(len(w)-i), *w[i:]))
    return bytes(b)


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
               <dword:32>       011   |35|  NO_MATCH          lit nnnnnnnn             out.addword(masked)
                                                                                       
                                111   | 3|  MATCH_8N_SQ1      seq                      out.copyword(lastOut)
   <masked:8>               0011010   |15|  MATCH_6N_2x4_SQ1  mask @16 m:nn            out.copybits(lastOut, masked, 8, 16)   or END_BLOCK
   <masked:8>               1011010   |15|  MATCH_6N_2x2_SQ1  mask @8 m:nn             out.copybits(lastOut, masked, 8, 8)
   <masked:8>                   110   |11|  MATCH_6N_2x0_SQ1  mask @0 m:nn             out.copybits(lastOut, masked, 8, 0)
   <masked:12>                11101   |17|  MATCH_5N_3x0_SQ1  mask @0 m:nnn            out.copybits(lastOut, masked, 12, 0)
   <masked:16>               001010   |22|  MATCH_4N_4x0_SQ1  mask @0 m:nnnn           out.copybits(lastOut, masked, 16, 0)

               <lastout:8>      001   |12|  MATCH_8N_SQ0      lookback  lb=nnn         out.copyword(lastOut)
   <masked:8>  <lastout:8>   101010   |23|  MATCH_6N_2x4_SQ0  mask @16 m:nn  lb=nnn    out.copybits(lastOut, masked, 8, 16)
   <masked:8>  <lastout:8>   111010   |23|  MATCH_6N_2x2_SQ0  mask @8 m:nn  lb=nnn     out.copybits(lastOut, masked, 8, 8)
   <masked:8>  <lastout:8>      000   |20|  MATCH_6N_2x0_SQ0  mask @0 m:nn  lb=nnn     out.copybits(lastOut, masked, 8, 0)
   <masked:12> <lastout:8>     0010   |25|  MATCH_5N_3x0_SQ0  mask @0 m:nnn  lb=nnn    out.copybits(lastOut, masked, 12, 0)
   <masked:16> <lastout:8>    01101   |30|  MATCH_4N_4x0_SQ0  mask @0 m:nnnn  lb=nnn   out.copybits(lastOut, masked, 16, 0)

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

        #  this is the only state of the algorithm.
        #  always a negative number from -2**LB+1 .. -1
        #  it is stored in the opcodes as  2^LB + lastOut
        lastOut = -1

        if self.debug:
            def log(msg):
                word = out.data[-1] if out.data else 0
                print(f"    [{out.len():04x}] {word:08x} {bits.pos:4x}:{bits.bitpos:2x} ({lastOut:4d}) {msg}")

            print("    outofs  outdata  ofs:bit last action")
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


class Q6zipSegment:
    """
    decode the header, dict and pointerlist of a q6zip segment,
    also provide access to the data chunks.
    """
    def __init__(self, fh, args):
        self.fh = fh
        self.basepos = fh.tell()
        data = fh.read(0x100000)
        o = 0
        npages, self.version = struct.unpack_from("<HH", data, o)
        o += 4

        # TODO: optionally heuristically determine dictsize

        dict1size, dict2size = self.splitdictsize(args.dictsize)

        self.dict1 = bytes2words(data[o:o+dict1size*4])
        o += dict1size*4
        self.dict2 = bytes2words(data[o:o+dict2size*4])
        o += dict2size*4

        self.ptrs = bytes2words(data[o:o+npages*4])
        o += npages*4

        self.datastart = o

        self.elfbase = self.ptrs[0] - o

        # TODO: analyze datachunks, to determine meta-boundary


    @staticmethod
    def splitdictsize(size):
        bits = []
        mask = 1
        while size and mask < 0x10000000:
            if size&mask:
                bits.append(mask)
                size &= ~mask
            mask <<= 1
        return bits


    @staticmethod
    def finddictsize(baseofs, data):
        # TODO
        pass

    def filepos2elfaddr(self, pos):
        return pos - self.basepos + self.elfbase
    def elfaddr2filepos(self, addr):
        return addr + self.basepos - self.elfbase

    def readchunk(self, ix):
        self.fh.seek(self.elfaddr2filepos(self.ptrs[ix]))
        if ix+1 < len(self.ptrs):
            size = self.ptrs[ix+1] - self.ptrs[ix]
        else:
            size = 0x1000
        return self.fh.read(size)


def dumpfile(fh, args):
    """
    hexdump the q6zip section at the current file position
    """
    q6 = Q6zipSegment(fh, args)

    print("p0 = %08x,  datastart=%08x" % (q6.ptrs[0], q6.datastart))

    o = q6.basepos
    print("%08x: npages=%d, ver=0x%04x" % (o, len(q6.ptrs), q6.version))
    o += 4
    print("%08x: dict1 - %d words" % (o, len(q6.dict1)))
    o += 4*len(q6.dict1)
    print("%08x: dict2 - %d words" % (o, len(q6.dict2)))
    o += 4*len(q6.dict2)
    print("%08x: ptrlist" % (o,))
    o += 4*len(q6.ptrs)
    print("%08x: compressed data" % (o,))

    for i, ofs in enumerate(q6.ptrs):
        cdata = q6.readchunk(i)

        cdata = bytes2words(cdata)

        if args.skipheader is None or i < args.skipheader:
            a0 = getchunkmeta(cdata[0])
            # (-1, 1..32, 0..4, 1..4)
            a1 = getchunkmeta(cdata[1])
            # (-1, 1..32, *, -4..2)

            cdata = cdata[2:]

            print("%08x: [%04x] (%s) (%s) (l=%03x) %s" % (ofs, i, a0, a1, len(cdata), " ".join("%08x" % _ for _ in cdata)))
        else:
            print("%08x: [%04x] %s" % (ofs, i, " ".join("%08x" % _ for _ in cdata)))


def processfile(fh, args):
    """
    decodes the q6zip section at the current file position
    """
    q6 = Q6zipSegment(fh, args)

    if args.output:
        ofh = open(args.output, "wb")
    elif not args.nooutput:
        ofh = sys.stdout.buffer
    else:
        ofh = None

    C = Q6Unzipper(q6.dict1, q6.dict2, args.lookback)
    C.debug = args.debug

    for i, ofs in [(args.page, q6.ptrs[args.page])] if args.page is not None else enumerate(q6.ptrs):
        if i+1<len(q6.ptrs):
            size = q6.ptrs[i+1]-ofs
        else:
            size = 0x1000

        if args.offset and args.offset!=ofs:
            continue
        cdata = q6.readchunk(i)
        cdata = bytes2words(cdata)

        if args.skipheader is None or i < args.skipheader:
            if args.debug:
                a0 = getchunkmeta(cdata[0]) # (-1, 1..32, 0..4, 1..4)
                a1 = getchunkmeta(cdata[1]) # (-1, 1..32, *, -4..2)
                print(f"[{i:04x}] {ofs:08x}-{ofs+size:08x}: ({a0}) ({a1})")
            cdata = cdata[2:]
        else:
            if args.debug:
                print(f"[{i:04x}] {ofs:08x}-{ofs+size:08x}")

        uncomp = C.decompress(cdata, args.maxout)
        udata = words2bytes(uncomp)

        if ofh:
            ofh.flush()
            ofh.write(udata)



def processhex(hexstr, args):
    data = bytes.fromhex(hexstr)

    with open(args.dictfile, "rb") as fh:
        q6 = Q6zipSegment(fh, args)

    C = Q6Unzipper(q6.dict1, q6.dict2, args.lookback)
    C.debug = args.debug

    uncomp = C.decompress(bytes2words(data), args.maxout)
    udata = words2bytes(uncomp)

    print(udata.hex())

class ElfReader:
    """
    wrapper translating ELF virtual addresses to file reads.
    """
    def __init__(self, fh):
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
    class Int(argparse.Action):
        """ argparse action to convert 0xNNN ints to integers """
        def __call__(self, parser, namespace, values, option_string=None):
            setattr(namespace, self.dest, int(values, 0))

    parser = argparse.ArgumentParser(description='Decompress packed q6zip ELF sections')
    parser.add_argument('--page', '-p', help='Which q6zip page to decompress', action=Int)
    parser.add_argument('--offset', '-o', help='Which q6zip offset to decompress', action=Int)
    parser.add_argument('--size', '-s', help='how many bytes to decompress', action=Int)
    parser.add_argument('--dump', help='hex dump of compressed data', action='store_true')
    parser.add_argument('--verbose', '-v', action='count')
    parser.add_argument('--debug', action='store_true', help="show all compression opcodes")
    parser.add_argument('--nooutput', '-n', action='store_true', help="don't output decompressed data")
    parser.add_argument('--output', type=str, help='Save output to file')
    parser.add_argument('--maxout', action=Int, help='how much words to decompress', default=0x400)

# TODO: automatically determine dictsize
    parser.add_argument('--dictsize', '-d', help='size of the dictionary in words', action=Int, default=0x4400)
    parser.add_argument('--dictfile', '-D', help='(for --hex) load dict from file', type=str)
    parser.add_argument('--baseoffset', '-O', help='(ELF) offset to the q6zip segment', action=Int, default=0)
    parser.add_argument('--lookback', help='lookback depth', type=int, default=8)
# TODO: automatically determine skipheader
    parser.add_argument('--skipheader', help='number of items with extra skip header', action=Int)

    parser.add_argument('--hex', type=str, help='uncompress hex data')

    parser.add_argument('elffile', help='Which file to process', type=str, nargs='?')
    args = parser.parse_args()

    if args.hex:
        # hex compressed data from the commandline
        processhex(args.hex, args)
    elif args.elffile:
        with open(args.elffile, "rb") as fh:
            elfmagic = fh.read(4)
            if elfmagic == b"\x7fELF":
                fh.seek(0)
                fh = ElfReader(fh)

            fh.seek(args.baseoffset)
            if args.dump:
                dumpfile(fh, args)
            else:
                processfile(fh, args)
    else:
        print("no inpput specified: either --hex or elffile")

if __name__=="__main__":
    main()

