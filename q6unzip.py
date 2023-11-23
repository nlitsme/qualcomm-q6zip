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
from binascii import b2a_hex

import ELF

if sys.version_info < (3, 0):
    stdout = sys.stdout
else:
    stdout = sys.stdout.buffer


def MASK(n):
    return (1<<n)-1

def bitlog(n):
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



class Q6Unzipper:
    """
    Decompresses data encoded using the following bit packed format:

    The data is packed with a variable length opcode, listed in the table below.
    Read the opcodes from right-to-left.

   <masked:8>  <lastout:9>      000   |  MATCH_6N_2x0_SQ0   -> into byte#0    'mask byte 3 nn'
               <lastout:9>      001   |  MATCH_8N_SQ0                         'lookback'
   <masked:12> <lastout:9>     0010   |  MATCH_5N_3x0_SQ0   -> into byte#0,1  'mask 12 bit 20 nnn'
               <dword:32>       011   |  NO_MATCH                             'uncompressed'
               <entry1:10>      100   |  DICT1_MATCH                          'dictionary1 nnn'
               <entry2:12>     0101   |  DICT2_MATCH                          'dictionary2 nnnn'
   <masked:8>                   110   |  MATCH_6N_2x0_SQ1   -> into byte#0    'mask byte 3 nn'
                                111   |  MATCH_8N_SQ1                         'sequential'
   <masked:16>               001010   |  MATCH_4N_4x0_SQ1   -> into byte#0,1  'mask 16 bit 16 nnnn'
   <masked:8>  <lastout:9>   101010   |  MATCH_6N_2x4_SQ0   -> into byte#2    'mask 16 bit 16 nn'
   <masked:8>  <lastout:9>   111010   |  MATCH_6N_2x2_SQ0   -> into byte#1    'mask byte 2 nn'
   <masked:8>               1011010   |  MATCH_6N_2x2_SQ1   -> into byte#1    'mask byte 2 nn'
   <masked:8>               0011010   |  MATCH_6N_2x4_SQ1   -> into byte#2    'mask 16 bit 16 nn'     or END_BLOCK
   <masked:12>                11101   |  MATCH_5N_3x0_SQ1   -> into byte#0,1  'mask 12 bit 20 nnn'
   <masked:16> <lastout:9>    01101   |  MATCH_4N_4x0_SQ0   -> into byte#0,1  'mask 16 bit 16 nnnn'


    00 <offset:lookbacklenbits>
    00 111 11 <0b10:lookbacklenbits>
    01 <index:tableNumBits>
    11 101 <offset:lookbacklenbits> <instr:16>
    """
    def __init__(self, dict1, dict2, lookback=8):
        self.debug = False

        self.dict1 = dict1
        self.dict2 = dict2

        self.LB_BITS = lookback

        self.DICT1_BITS = bitlog(len(dict1))
        self.DICT2_BITS = bitlog(len(dict2))

    def decompress(self, compressed):
        """
        Decompresses data from a byte array `compressed`, returning the uncompressed data bytes.
        """
        bits = BitStreamReader(compressed)
        out = BitStreamWriter()

        lastOut = -1        #  this is the only state of the algorithm.

        if self.debug:
            def log(msg):
                print("    [%4x] %4x:%2d  %08X (%u) %s" % (out.len(), bits.pos, bits.bitpos, out.data[-1] if out.data else 0, lastOut, msg))

            print("    outofs  ofs:bit  outdata last action")
        else:
            def log(msg):
                pass

        try:
            while out.len()<0x400:
                op1 = bits.get(3)
                if op1 == 0:  # MATCH_6N_2x0_SQ0 set lastout, byte from stream
                    lastOut = bits.get(self.LB_BITS) - (1<<self.LB_BITS)
                    masked = bits.get(8)
                    out.copybits(lastOut, masked, 8, 0)

                    log("mask byte 3 %02x" % (masked))
                elif op1 == 1:  # MATCH_8N_SQ0 set lastout, dword from lastout
                    lastOut = bits.get(self.LB_BITS) - (1<<self.LB_BITS)
                    out.copyword(lastOut)

                    log("lookback")
                elif op1 == 2:
                    if bits.get(1)==0: # MATCH_5N_3x0_SQ0        -- setting lastOut
                        lastOut = bits.get(self.LB_BITS) - (1<<self.LB_BITS)
                        masked = bits.get(12)
                        out.copybits(lastOut, masked, 12, 0)
                        log("mask 12 bit 20 %03X" % (masked))
                    else:
                        op2 = bits.get(2)
                        if op2==0: # MATCH_4N_4x0_SQ1   -- reusing 'lastOut'
                            masked = bits.get(16)
                            out.copybits(lastOut, masked, 16, 0)
                            log("mask 16 bit 16 %04X" % (masked))
                        elif op2==2: # MATCH_6N_2x4_SQ0        -- setting lastOut
                            lastOut = bits.get(self.LB_BITS) - (1<<self.LB_BITS)
                            masked = bits.get(8)
                            out.copybits(lastOut, masked, 8, 16)
                            log("mask 16 bit 16 %02X" % (masked))
                        elif op2==3: # MATCH_6N_2x2_SQ0        -- setting lastOut
                            lastOut = bits.get(self.LB_BITS) - (1<<self.LB_BITS)
                            masked = bits.get(8)
                            out.copybits(lastOut, masked, 8, 8)
                            log("mask byte 2 %02X" % (masked))
                        elif bits.get(1): # MATCH_6N_2x2_SQ1   -- reusing 'lastOut'
                            masked = bits.get(8)
                            out.copybits(lastOut, masked, 8, 8)
                            log("mask byte 2 %02X" % (masked))
                        else: # MATCH_6N_2x4_SQ1    -- reusing 'lastOut'
                            masked = bits.get(8)
                            if masked != 0xFF:
                                # .. in the modem.elf binary a check is here for masked==0xff -> stop
                                out.copybits(lastOut, masked, 8, 16)
                                log("mask 16 bit 16 %02X" % (masked))
                            else:
                                log("mask 16 bit 16 FF -> break")
                elif op1 == 3: # NO_MATCH
                    masked = bits.get(32)
                    out.addword(masked)
                    log("uncompressed")
                elif op1 == 4: # DICT1_MATCH
                    entry = bits.get(self.DICT1_BITS)
                    out.addword(self.dict1[entry])
                    log("dictionary1 %03x" % entry)
                elif op1 == 5:
                    if bits.get(1)==0: # DICT2_MATCH
                        entry = bits.get(self.DICT2_BITS)
                        out.addword(self.dict2[entry])
                        log("dictionary2 %04x" % entry)
                    else:
                        if bits.get(1): # MATCH_5N_3x0_SQ1   -- reusing 'lastOut'
                            masked = bits.get(12)
                            out.copybits(lastOut, masked, 12, 0)
                            log("mask 12 bit 20 %03x" % masked)
                        else: # MATCH_4N_4x0_SQ0        -- setting lastOut
                            lastOut = bits.get(self.LB_BITS) - (1<<self.LB_BITS)
                            masked = bits.get(16)
                            out.copybits(lastOut, masked, 16, 0)
                            log("mask 16 bit 16 %04x" % masked)
                elif op1 == 6:   # MATCH_6N_2x0_SQ1 byte from stream   -- reusing 'lastOut'
                    masked = bits.get(8)
                    out.copybits(lastOut, masked, 8, 0)
                    log("mask byte 3 %02x" % masked)
                elif op1 == 7:   # MATCH_8N_SQ1  dword from lastout   -- reusing 'lastOut'
                    out.copyword(lastOut)
                    log("sequential")
                else:
                    print("unexpected op", op1)

        except EOFError:
            log("EOF")
        finally:
            log("done")

        return out.data


def bytes2intlist(data):
    if len(data) % 4:
        print("WARNING: unaligned data: %s" % (b2a_hex(data)))
    return struct.unpack("<%dL" % (len(data)//4), data)

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
    if value >= 2**(bits-1):
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

    fh.seek(elf.virt2file(args.offset))

    npages, unknown = struct.unpack("<HH", fh.read(4))

    dict1size, dict2size = splitdictsize(args.dictsize)
    dict1 = bytes2intlist(fh.read(dict1size*4))
    dict2 = bytes2intlist(fh.read(dict2size*4))

    ptrs = bytes2intlist(fh.read(npages*4))
    datastart = args.offset + 4 + args.dictsize*4 + npages*4
    dataend = elf.virtend(args.offset)
    
    if args.verbose:
        print("p0 = %08x,  datastart=%08x, filepos=%08x" % (ptrs[0], datastart , fh.tell()))

    if args.dump:
        print("%08x: npages=%d, unk=0x%04x" % (args.offset, npages, unknown))
        print("%08x: dict1 - %d words" % (args.offset+4, dict1size))
        print("%08x: dict2 - %d words" % (args.offset+4+4*dict1size, dict2size))
        print("%08x: ptrlist" % (args.offset+4+4*dict1size+4*dict2size))
        print("%08x: compressed data" % (args.offset+4+4*dict1size+4*dict2size+4*npages))
        for i, (ofs, nextofs) in enumerate(zip(ptrs, ptrs[1:]+(dataend,))):
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

        for i, (ofs, nextofs) in enumerate(zip(ptrs, ptrs[1:]+(dataend,))):
            fh.seek(elf.virt2file(ofs))
            cdata = fh.read(nextofs-ofs)

            if i < args.skipheader:
                cdata = cdata[8:]

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

def rawuncomp(fh, args):
    """ note: args.offset has a different meaning for this function """
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

    uncomp = C.decompress(bytes2intlist(cdata))
    udata = intlist2bytes(uncomp)

    print("comp    : %s" % b2a_hex(cdata))
    print("full    : %s" % b2a_hex(udata))


def main():
    parser = argparse.ArgumentParser(description='Decompress packed q6zip ELF sections')
    parser.add_argument('--offset', '-o', help='Which q6zip section to decompress', type=str, required=True)
    parser.add_argument('--size', '-s', help='how many bytes to decompress', type=str)
    parser.add_argument('--dump', help='hex dump of compressed data', action='store_true')
    parser.add_argument('--verbose', '-v', action='count')
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--nooutput', '-n', action='store_true')
    parser.add_argument('--output', type=str, help='Save output to file')

    parser.add_argument('--dictsize', '-d', help='size of the dictionary in words', type=str, default='0x4400')
    parser.add_argument('--lookback', help='lookback depth', type=str, default='8')
    parser.add_argument('--skipheader', help='number of items with extra skip header', type=str, default='0xf7a') # for quectel

    parser.add_argument('--dict1', help='where is dict1', type=str)
    parser.add_argument('--dict2', help='where is dict2', type=str)

    parser.add_argument('elffile', help='Which file to process', type=str)
    args = parser.parse_args()

    if args.offset is not None:
        args.offset = int(args.offset, 0)
    if args.size is not None:
        args.size = int(args.size, 0)
    if args.dictsize is not None:
        args.dictsize = int(args.dictsize , 0)
    if args.lookback is not None:
        args.lookback = int(args.lookback , 0)
    if args.skipheader is not None:
        args.skipheader = int(args.skipheader , 0)

    with open(args.elffile, "rb") as fh:
        if args.dict1 and args.dict2:
            rawuncomp(fh, args)
        else:
            processfile(fh, args)

if __name__=="__main__":
    main()

