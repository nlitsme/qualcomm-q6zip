"""
Tool for compressing q6zip compressed CODE sections.

Author: Willem Hengeveld <itsme@gsmk.de>

TODO: add code to compress entire files.
TODO: automatically add 'break' position information.

entries with breaks have two 'metadata' words:

    lastseq0:10, bitsleft0:6, indelta0:10, outdelta0:6
    lastseq1:10, bitsleft1:6, indelta1:10, outdelta1:6

where the 'lastseq' fields are always -1
    the first break is at in-pos:  word:indelta0, bit:32-bitsleft0,  and out-pos: outdelta0
    the second break is at in-pos:  word:indelta0+indelta1, bit:32-bitsleft1,  and out-pos: 0x200+outdelta0+outdelta1

the break is always inserted after a complete hexagon instruction packet.
  -> with PP bits either 00(duplex) or 11(end)

"""
from __future__ import division, print_function
from dataclasses import dataclass
from abc import ABC, abstractmethod
from collections import defaultdict
import sys
import re
import struct
import argparse

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


class WordStreamReader:
    """
    simple word array reader.
    """
    def __init__(self, data):
        self.data = data
        self.pos = 0

        # mask => word => abspos
        self.lookup = {}

        self.addmask(0)

    def len(self):
        return len(self.data)

    def eof(self):
        return self.pos == len(self.data)

    def nextword(self):
        if self.pos:
            # add previous word to the index.
            self.addtoindex(self.data[self.pos-1], self.pos-1)

        # return current word and advance position.
        w = self.data[self.pos]
        self.pos += 1
        return w

    def addmask(self, mask):
        self.lookup[mask] = {}

    def addtoindex(self, word, abspos):
        """ update all lookup indices with this new word """
        for m, ix in self.lookup.items():
            ix[word & ~m] = abspos

    def findlookback(self, word, mask, lbrange):
        """ search the lookup index corresponding to the specified mask """
        abspos = self.lookup[mask].get(word & ~mask)
        if abspos is not None:
            delta = abspos - self.pos + 1
            if delta >= 0:
                print(f"unexpected positive delta: w={word:x}, m={mask:x}, abspos={abspos:x}, pos={self.pos:x}")
            if delta <= -lbrange:
                return
            return delta + lbrange

class BitStreamWriter:
    """
    write bits to a stream of 32-bit words.
    """
    def __init__(self):
        self.data = []
        self.bitpos = 0
        self.value = 0

    def put(self, value, n):
        self.value |= value<<self.bitpos
        self.bitpos += n
        while self.bitpos >= 32:
            self.data.append(self.value&0xFFFFFFFF)
            self.value >>= 32
            self.bitpos -= 32

    def flush(self):
        self.data.append(self.value)
        self.value = self.bitpos = 0

@dataclass
class Operation:
    """
    baseclass for compression operations
    """
    code : int
    codelen : int     # nr of bits in the code
    qcomorder : int   # op ordering used by qualcomm
    masklen : int     # mask bitlen
    arglen : int      # non mask arg bitlen

    class MatchBase:
        def __init__(self, op):
            """ subclasses may have more parameters """
            self.op = op

        @abstractmethod
        def encode(self, zipper, bits) -> None:
            """ encode both the opcode and parameters of this operation """
            ...
    @abstractmethod
    def matches(self, word, zipper, words) -> MatchBase:
        """ returns a MatchBase subclass when the word matches this operation """
        ...

    def bitsize(self) -> int:
        """ return the total size in bits of this operation """
        return self.codelen + self.masklen + self.arglen



class Sequential(Operation):
    """
    Construct as:
                      code, l, qc, m,  arglen
    Sequential(      0b111, 3,  1, 0,  0),                # MATCH_8N_SQ1       .copyword(lastOut)

    outputs op: 111
    When decompressing, repeats the previous outputted word.
    """
    class Match(Operation.MatchBase):
        def __init__(self, op):
            self.op = op
        def encode(self, zipper, bits):
            bits.put(self.op.code, self.op.codelen)
        def __repr__(self):
            return f"seq"

    def matches(self, word, zipper, words):
        p = words.pos-1+zipper.lastOut
        if p>=0 and words.data[p] == word:
            return self.Match(self)

    def __repr__(self):
        return f"seq"

class Lookback(Operation):
    """
    Construct as:
                      code, l, qc, m,  arglen
    Lookback(        0b001, 3,  3, 0, self.LB_BITS),      # MATCH_8N_SQ0       .copyword(lastOut)

    outpus op: <lookback> 001
    When decompressing, repeats the word 'lookback' items back.
    """
    class Match(Operation.MatchBase):
        def __init__(self, op, lb):
            self.op = op
            self.lb = lb
        def encode(self, zipper, bits):
            bits.put(self.op.code, self.op.codelen)
            bits.put(self.lb, zipper.LB_BITS)
            zipper.lastOut = self.lb-2**zipper.LB_BITS
        def __repr__(self):
            return f"lookback  lb={self.lb:03x}"

    def matches(self, word, zipper, words):
        lbrange = 2**zipper.LB_BITS
        i = words.findlookback(word, 0, lbrange)
        if i is not None:
            return self.Match(self, i)

    def __repr__(self):
        return f"lookback"

class Dict(Operation):
    """
    Construct in one of the following ways:
                      code, l, qc, m,  arglen
    Dict(            0b100, 3,  4, 0, self.DICT1_BITS),   # DICT1_MATCH        .addword(self.dict1[entry])
    Dict(           0b0101, 4,  7, 0, self.DICT2_BITS),   # DICT2_MATCH        .addword(self.dict2[entry])

    outputs op: <index> {100|0101}
    When decompressing, inserts the word at the specified dictionary location.
    """
    class Match(Operation.MatchBase):
        def __init__(self, op, ent):
            self.op = op
            self.ent = ent
        def encode(self, zipper, bits):
            bits.put(self.op.code, self.op.codelen)
            bits.put(self.ent, self.op.arglen)
        def __repr__(self):
            if self.op.arglen<12:
                return f"dict1 {self.ent:03x}"
            else:
                return f"dict2 {self.ent:04x}"

    def matches(self, word, zipper, words):
        #print(f"matching dict l={self.arglen} to {word:08x}")
        d = zipper.getdict(self.arglen)
        i = d.get(word)
        if i is not None:
            return self.Match(self, i)

    def __repr__(self):
        return f"dict(l={self.arglen})"

class Literal(Operation):
    """
    Construct as:
                      code, l, qc, m,  arglen
    Literal(         0b011, 3, 15, 0, 32),                # NO_MATCH           .addword(masked)

    outputs op: <word> 011
    When decompressing outputs the specifeid literal word.
    """
    class Match(Operation.MatchBase):
        def __init__(self, op, w):
            self.op = op
            self.w = w 
        def encode(self, zipper, bits):
            bits.put(self.op.code, self.op.codelen)
            bits.put(self.w, 32)
        def __repr__(self):
            return f"lit {self.w:08x}"

    def matches(self, word, zipper, words):
        return self.Match(self, word)

    def __repr__(self):
        return f"literal"

class LookbackMask(Operation):
    """
    Construct in one of the following ways:
                      code, l, qc, m,    arglen    bitofs
    LookbackMask( 0b101010, 6, 12, 8, self.LB_BITS,16),   # MATCH_6N_2x4_SQ0   .copybits(lastOut, masked,  8,16)
    LookbackMask( 0b111010, 6, 11, 8, self.LB_BITS, 8),   # MATCH_6N_2x2_SQ0   .copybits(lastOut, masked,  8, 8)
    LookbackMask(    0b000, 3,  9, 8, self.LB_BITS, 0),   # MATCH_6N_2x0_SQ0   .copybits(lastOut, masked,  8, 0)
    LookbackMask(   0b0010, 4, 13,12, self.LB_BITS, 0),   # MATCH_5N_3x0_SQ0   .copybits(lastOut, masked, 12, 0)
    LookbackMask(  0b01101, 5, 14,16, self.LB_BITS, 0),   # MATCH_4N_4x0_SQ0   .copybits(lastOut, masked, 16, 0)

    outputs op: <masked> <lookback> {0010|101010|01101|111010|000}

    When decompressing, outputs the specified previous word, with the masked bits replaced with the 'mask' value.
    """
    class Match(Operation.MatchBase):
        def __init__(self, op, m, lb):
            self.op = op
            self.m = m
            self.lb = lb
        def encode(self, zipper, bits):
            bits.put(self.op.code, self.op.codelen)
            bits.put(self.lb, zipper.LB_BITS)
            bits.put(self.m, self.op.masklen)
            zipper.lastOut = self.lb-2**zipper.LB_BITS
        def __repr__(self):
            if self.op.masklen== 8: m = f"{self.m:02x}"
            elif self.op.masklen== 12: m = f"{self.m:03x}"
            elif self.op.masklen== 16: m = f"{self.m:04x}"
            return f"mask @{self.op.bitofs} m:{m}  lb={self.lb:03x}"

    def __init__(self, *args):
        super().__init__(*args[:-1])
        self.bitofs = args[-1]

    def getmask(self):
        return MASK(self.masklen)<<self.bitofs

    def matches(self, word, zipper, words):
        mask = self.getmask()
        lbrange = 2**zipper.LB_BITS
        i = words.findlookback(word, mask, lbrange)
        if i is not None:
            return self.Match(self, (word&mask)>>self.bitofs, i)

    def __repr__(self):
        return f"mask @{self.bitofs} m:{'n'*(self.masklen//4)}  lb=nnn"

class Mask(Operation):
    """
    Construct in one of the following ways:
                      code, l, qc, m, a  bitofs
    Mask(        0b0011010, 7,  6, 8, 0,16),              # MATCH_6N_2x4_SQ1   .copybits(lastOut, masked,  8,16)   or END_BLOCK
    Mask(        0b1011010, 7,  5, 8, 0, 8),              # MATCH_6N_2x2_SQ1   .copybits(lastOut, masked,  8, 8)
    Mask(            0b110, 3,  2, 8, 0, 0),              # MATCH_6N_2x0_SQ1   .copybits(lastOut, masked,  8, 0)
    Mask(          0b11101, 5,  8,12, 0, 0),              # MATCH_5N_3x0_SQ1   .copybits(lastOut, masked, 12, 0)
    Mask(         0b001010, 6, 10,16, 0, 0),              # MATCH_4N_4x0_SQ1   .copybits(lastOut, masked, 16, 0)

    outputs op: <masked> {11101|011010|001010|1011010|110}

    When decompressing, repeats the most recent value, with the masked bits replaced.
    """
    class Match(Operation.MatchBase):
        def __init__(self, op, m):
            self.op = op
            self.m = m
        def encode(self, zipper, bits):
            bits.put(self.op.code, self.op.codelen)
            bits.put(self.m, self.op.masklen)
        def __repr__(self):
            if self.op.masklen== 8: m = f"{self.m:02x}"
            elif self.op.masklen== 12: m = f"{self.m:03x}"
            elif self.op.masklen== 16: m = f"{self.m:04x}"
            return f"mask @{self.op.bitofs} m:{m}"


    def __init__(self, *args):
        super().__init__(*args[:-1])
        self.bitofs = args[-1]

    def matches(self, word, zipper, words):
        p = words.pos-1+zipper.lastOut
        if p<0:
            return

        mask = MASK(self.masklen)<<self.bitofs
        if words.data[p] & ~mask == word & ~mask:
            m = (word&mask)>>self.bitofs
            if self.code == 0b0011010 and m==0xff:
                # don't emit break as regular mask opcode.
                return
            return self.Match(self, m)

    def __repr__(self):
        return f"mask @{self.bitofs} m:{'n'*(self.masklen//4)}"

class Break(Operation):
    """
    Breaks are inserted only in some compressed blocks.
    They allow half a block to be decompressed.
    """
    def __init__(self):
        super().__init__( 0b0011010, 7, 0, 8, 0)

    def encode(self, bits):
        # TODO - this does not follow the pattern of the other ops with a match object.
        bits.put(self.code, self.codelen)
        bits.put(0xFF, self.masklen)

    def __repr__(self):
        return f"break"

class Q6Zipper:
    def __init__(self, args):
        self.debug = args.debug
        self.dict1 = None
        self.dict2 = None

        self.LB_BITS = args.lookback

        self.DICT1_BITS = args.dict1bits
        self.DICT2_BITS = args.dict2bits

        """  order used by qualcomm
         1   3 MATCH_8N_SQ1      seq
         2  11 MATCH_6N_2x0_SQ1  mask @0 m:nn
         3  11 MATCH_8N_SQ0      lookback
         4  13 DICT1_MATCH       dict(l=10)
         5  15 MATCH_6N_2x2_SQ1  mask @8 m:nn
         6  15 MATCH_6N_2x4_SQ1  mask @16 m:nn
         7  18 DICT2_MATCH       dict(l=14)
         8  17 MATCH_5N_3x0_SQ1  mask @0 m:nnn
         9  19 MATCH_6N_2x0_SQ0  mask @0 m:nn  lb=nnn
        10  22 MATCH_4N_4x0_SQ1  mask @0 m:nnnn
        11  22 MATCH_6N_2x2_SQ0  mask @8 m:nn  lb=nnn
        12  22 MATCH_6N_2x4_SQ0  mask @16 m:nn  lb=nnn
        13  24 MATCH_5N_3x0_SQ0  mask @0 m:nnn  lb=nnn
        14  29 MATCH_4N_4x0_SQ0  mask @0 m:nnnn  lb=nnn
        15  35 NO_MATCH          literal
        """
        self.ops = [    #   code clen   #  m arg  [bitpos]
            Dict(            0b100, 3,  4, 0, self.DICT1_BITS),   # DICT1_MATCH        .addword(self.dict1[entry])
            Dict(           0b0101, 4,  7, 0, self.DICT2_BITS),   # DICT2_MATCH        .addword(self.dict2[entry])
            Literal(         0b011, 3, 15, 0, 32),                # NO_MATCH           .addword(masked)

            Sequential(      0b111, 3,  1, 0, 0),                 # MATCH_8N_SQ1       .copyword(lastOut)
            Mask(        0b0011010, 7,  6, 8, 0,16),              # MATCH_6N_2x4_SQ1   .copybits(lastOut, masked,  8,16)   or END_BLOCK or END_BLOCK
            Mask(        0b1011010, 7,  5, 8, 0, 8),              # MATCH_6N_2x2_SQ1   .copybits(lastOut, masked,  8, 8)
            Mask(            0b110, 3,  2, 8, 0, 0),              # MATCH_6N_2x0_SQ1   .copybits(lastOut, masked,  8, 0)
            Mask(          0b11101, 5,  8,12, 0, 0),              # MATCH_5N_3x0_SQ1   .copybits(lastOut, masked, 12, 0)
            Mask(         0b001010, 6, 10,16, 0, 0),              # MATCH_4N_4x0_SQ1   .copybits(lastOut, masked, 16, 0)

            Lookback(        0b001, 3,  3, 0, self.LB_BITS),      # MATCH_8N_SQ0       .copyword(lastOut)
            LookbackMask( 0b101010, 6, 12, 8, self.LB_BITS,16),   # MATCH_6N_2x4_SQ0   .copybits(lastOut, masked,  8,16)
            LookbackMask( 0b111010, 6, 11, 8, self.LB_BITS, 8),   # MATCH_6N_2x2_SQ0   .copybits(lastOut, masked,  8, 8)
            LookbackMask(    0b000, 3,  9, 8, self.LB_BITS, 0),   # MATCH_6N_2x0_SQ0   .copybits(lastOut, masked,  8, 0)
            LookbackMask(   0b0010, 4, 13,12, self.LB_BITS, 0),   # MATCH_5N_3x0_SQ0   .copybits(lastOut, masked, 12, 0)
            LookbackMask(  0b01101, 5, 14,16, self.LB_BITS, 0),   # MATCH_4N_4x0_SQ0   .copybits(lastOut, masked, 16, 0)
        ]

        # sort by bit-size
        if args.qcomorder:
            self.ops = sorted(self.ops, key=lambda e:e.qcomorder)
        else:
            self.ops = sorted(self.ops, key=lambda e:e.bitsize())

        self.breakpos0 = self.breakpos1 = None

        self.reset()

    def reset(self):
        self.lastOut = -1    # the compressor state.

    def loaddict(self, dict1, dict2):
        self.dict1 = { w:i for i, w in enumerate(dict1) }
        self.dict2 = { w:i for i, w in enumerate(dict2) }

    def getdict(self, bits):
        if bits == self.DICT1_BITS: return self.dict1
        if bits == self.DICT2_BITS: return self.dict2

    def makedict(self, data):
        #  count all dwords, sort by occurrence.
        #  first 1024 in dict1, next 16k in dict2
        #  note that this will not very likely result in the exact same dicts as the qualcomm zipper has,
        #  since dict ordering is different across platforms.
        xref = defaultdict(int)
        for w in data:
            xref[w] += 1
        sortedxref = list(sorted(xref.items(), key=lambda kv: (-kv[1], kv[0])))
        dict1 = [kv[0] for kv in sortedxref[:2**self.DICT1_BITS]]
        sortedxref = sortedxref[2**self.DICT1_BITS:]
        dict2 = [kv[0] for kv in sortedxref[:2**self.DICT2_BITS]]

        self.loaddict(dict1, dict2)

    def compress(self, data):
        """
        input: words
        returns: bytes
        """
        words = WordStreamReader(data)

        # register masks which need special indexing to inputstream
        for op in self.ops:
            if isinstance(op, LookbackMask):
                words.addmask(op.getmask())

        bits = BitStreamWriter()
 
        word = None
        if self.debug:
            def log(obj):
                print(f"    [{words.pos:04x}] {word:08x} {len(bits.data):4x}:{bits.bitpos:2x} ({self.lastOut:4d}) {obj}")
            print("    outofs  outdata  ofs:bit last action")
        else:
            def log(obj):
                pass

        while not words.eof():
            word = words.nextword()
 
            for op in self.ops:
                if m := op.matches(word, self, words):
                    m.encode(self, bits)
                    log(m)
                    break
            if self.needbreak(words, bits):
                op = Break()
                op.encode(bits)

                log(op)

        # the final break
        op = Break()
        op.encode(bits)
        log(op)
        bits.flush()

        return bits.data
 
    def needbreak(self, words, bits):
        if self.breakpos0 == words.pos:
            self.breakpos0 = None
            return True
        if self.breakpos1 == words.pos:
            self.breakpos1 = None
            return True

    def compresswithbreaks(self, data):
        """
        input: words
        returns: [words...], bytes

        note that compresswithbreaks must only be used on code sections.
        data will not work, because this required the code to have hexagon code packets.

        meta:
            [a.wrd]  a.ofs:a.bit  -> ( 20-a.bit, a.ofs,       a.wrd)
            [b.wrd]  b.ofs:b.bit  -> ( 20-b.bit, b.ofs-a.ofs, b.wrd-a.wrd-200)
        """
        if type(data)==bytes:
            raise Exception("need a word-array")
        words = WordStreamReader(data)

        # register masks which need special indexing to inputstream
        for op in self.ops:
            if isinstance(op, LookbackMask):
                words.addmask(op.getmask())

        bits = BitStreamWriter()
        meta = []
 
        word = None
        if self.debug:
            def log(obj):
                print(f"    [{words.pos:04x}] {word:08x} {len(bits.data):4x}:{bits.bitpos:2x} ({self.lastOut:4d}) {obj}")
            print("    outofs  outdata  ofs:bit last action")
        else:
            def log(obj):
                pass

        needbreak = True
        while not words.eof():
            word = words.nextword()
            if words.pos==0x200 and len(meta)==1:
                needbreak = True
                log("wantbreak")
 
            for op in self.ops:
                if m := op.matches(word, self, words):
                    m.encode(self, bits)
                    log(m)
                    break
            else:
                print("?? there should always be a match")

            if (word>>14)&3 in (0, 3):
                if needbreak:
                    op = Break()
                    op.encode(bits)
                    log(op)

                    prevout = meta[-1][1] if meta else 0
                    previn = meta[-1][2]+0x200 if meta else 0
                    meta.append((32-bits.bitpos, len(bits.data)-prevout, words.pos-previn))
                    needbreak = False

        # the final break
        op = Break()
        op.encode(bits)
        log(op)

        bits.flush()

        def makemetaword(lastseq, bitsleft, indelta, outdelta):
            #print(f"m: ({lastseq:4x},{bitsleft:2x},{indelta:4x},{outdelta:2x}) -> ", end="")
            if lastseq<0: lastseq += 1024
            if outdelta<0: outdelta += 64
            m = (lastseq|(bitsleft<<10)) | ((indelta|(outdelta<<10))<<16)
            #print(f"{m:08x}")
            return m

        meta = [makemetaword(-1, bitsleft, indelta, outdelta) for bitsleft, indelta, outdelta in meta]

        return meta, bits.data
 
def main():
    parser = argparse.ArgumentParser(description='Compress data using q6zip compression')
    parser.add_argument('--offset', '-o', help='Which section to compress', type=str, default='0')
    parser.add_argument('--length', '-l', help='how many bytes to compress', type=str, default='0x1000')
    parser.add_argument('--dict1', help='offset:length to dict1', type=str, default='4:0x1000')
    parser.add_argument('--dict2', help='offset:length to dict2', type=str, default='0x1004:0x10000')
    parser.add_argument('--dictfile', help='load dict from', type=str)
    parser.add_argument('--lookback', help='lookback depth', type=int, default=8)
    parser.add_argument('--breakpos0', help='load dict from', type=str)
    parser.add_argument('--breakpos1', help='load dict from', type=str)
    parser.add_argument('--debug', action='store_true', help="show all compression opcodes")
    parser.add_argument('--qcomorder', action='store_true', help="prioritize opcodes in qualcomm order.")

    parser.add_argument('srcfile', help='Which file to process', type=str)
    args = parser.parse_args()

    if args.offset is not None:
        args.offset = int(args.offset, 0)
    if args.length is not None:
        args.length = int(args.length, 0)
    if args.breakpos0 is not None:
        args.breakpos0 = int(args.breakpos0, 0)
    if args.breakpos1 is not None:
        args.breakpos1 = int(args.breakpos1, 0)

    # fileoffset : bytesize
    if m := re.match(r'(\w+):(\w+)', args.dict1):
        args.dict1ofs = int(m[1],0)
        args.dict1bits = bitlog(int(m[2],0))-2
    if m := re.match(r'(\w+):(\w+)', args.dict2):
        args.dict2ofs = int(m[1],0)
        args.dict2bits = bitlog(int(m[2],0))-2

    with open(args.dictfile, "rb") as fh:
        fh.seek(args.dict1ofs)
        dict1 = fh.read(4*2**args.dict1bits)
        dict1 = struct.unpack(f"<{len(dict1)//4}L", dict1)

        fh.seek(args.dict2ofs)
        dict2 = fh.read(4*2**args.dict2bits)
        dict2 = struct.unpack(f"<{len(dict2)//4}L", dict2)
        
    with open(args.srcfile, "rb") as fh:
        fh.seek(args.offset)
        data = fh.read(args.length)

        data = struct.unpack(f"<{len(data)//4}L", data)

        C = Q6Zipper(args)
        C.loaddict(dict1, dict2)

        if args.breakpos0 is not None:
            C.breakpos0 = args.breakpos0
        if args.breakpos1 is not None:
            C.breakpos1 = args.breakpos1

        res = C.compress(data)
    
    res = struct.pack(f"<{len(res)}L", *res)

    if not args.debug:
        print(res.hex())

if __name__=="__main__":
    main()

