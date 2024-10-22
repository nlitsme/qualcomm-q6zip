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
    Output stream which can duplicate values pushed to it at an earlier time.
    """
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def len(self):
        return len(self.data)

    def eof(self):
        return self.pos == len(self.data)

    def nextword(self):
        self.pos += 1
        return self.data[self.pos-1]

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

    @abstractmethod
    def matches(self, word, zipper, indata) -> bool: ...

    def bitsize(self):
        return self.codelen + self.masklen + self.arglen

    class MatchBase:
        def __init__(self, op):
            self.op = op

        @abstractmethod
        def output(self, zipper, out) -> None: ...


class Sequential(Operation):
    """
    Construct as: Sequential(      0b111, 3,  1, 0,  0),                # MATCH_8N_SQ1       out.copyword(lastOut)
    outputs op: 111
    When decompressing, repeats the previous outputted word.
    """
    class Match(Operation.MatchBase):
        def __init__(self, op):
            self.op = op
        def output(self, zipper, out):
            out.put(self.op.code, self.op.codelen)
        def __repr__(self):
            return f"seq"

    def matches(self, word, zipper, indata):
        p = indata.pos-1+zipper.lastOut
        if p>=0 and indata.data[p] == word:
            return self.Match(self)

    def __repr__(self):
        return f"seq"

class Lookback(Operation):
    """
    Construct as: Lookback(        0b001, 3,  3, 0, self.LB_BITS),      # MATCH_8N_SQ0       out.copyword(lastOut)
    outpus op: <lookback> 001
    When decompressing, repeats the word 'lookback' items back.
    """
    class Match(Operation.MatchBase):
        def __init__(self, op, lb):
            self.op = op
            self.lb = lb
        def output(self, zipper, out):
            out.put(self.op.code, self.op.codelen)
            out.put(self.lb, zipper.LB_BITS)
            zipper.lastOut = self.lb-2**zipper.LB_BITS
        def __repr__(self):
            return f"lookback  lb={self.lb:03x}"

    def matches(self, word, zipper, indata):
        lbrange = 2**zipper.LB_BITS
        # 0 ..   pos-2-(2**LB-1)  ..   pos-2-0 [pos-1:word]
        for i in range(max(0, indata.pos-2-(lbrange-1)), indata.pos-1):
            if indata.data[i] == word:
                return self.Match(self, lbrange-(indata.pos-1-i))
    def __repr__(self):
        return f"lookback"

class Dict(Operation):
    """
    Construct in one of the following ways:
    Dict(            0b100, 3,  4, 0, self.DICT1_BITS),   # DICT1_MATCH        out.addword(self.dict1[entry])
    Dict(           0b0101, 4,  7, 0, self.DICT2_BITS),   # DICT2_MATCH        out.addword(self.dict2[entry])
    outputs op: <index> {100|0101}
    When decompressing, inserts the word at the specified dictionary location.
    """
    class Match(Operation.MatchBase):
        def __init__(self, op, ent):
            self.op = op
            self.ent = ent
        def output(self, zipper, out):
            out.put(self.op.code, self.op.codelen)
            out.put(self.ent, self.op.arglen)
        def __repr__(self):
            if self.op.arglen<12:
                return f"dict1 {self.ent:03x}"
            else:
                return f"dict2 {self.ent:04x}"

    def matches(self, word, zipper, indata):
        #print(f"matching dict l={self.arglen} to {word:08x}")
        for i, w in enumerate(zipper.getdict(self.arglen)):
            #print(f" testing {w:08x} @{i:04x}")
            if w==word:
                return self.Match(self, i)

    def __repr__(self):
        return f"dict(l={self.arglen})"

class Literal(Operation):
    """
    Construct as: Literal(         0b011, 3, 15, 0, 32),                # NO_MATCH           out.addword(masked)
    outputs op: <word> 011
    When decompressing outputs the specifeid literal word.
    """
    class Match(Operation.MatchBase):
        def __init__(self, op, w):
            self.op = op
            self.w = w 
        def output(self, zipper, out):
            out.put(self.op.code, self.op.codelen)
            out.put(self.w, 32)
        def __repr__(self):
            return f"lit {self.w:08x}"

    def matches(self, word, zipper, indata):
        return self.Match(self, word)

    def __repr__(self):
        return f"literal"

class LookbackMask(Operation):
    """
    Construct in one of the following ways:
    LookbackMask( 0b101010, 6, 12, 8, self.LB_BITS,16),   # MATCH_6N_2x4_SQ0   out.copybits(lastOut, masked,  8,16)
    LookbackMask( 0b111010, 6, 11, 8, self.LB_BITS, 8),   # MATCH_6N_2x2_SQ0   out.copybits(lastOut, masked,  8, 8)
    LookbackMask(    0b000, 3,  9, 8, self.LB_BITS, 0),   # MATCH_6N_2x0_SQ0   out.copybits(lastOut, masked,  8, 0)
    LookbackMask(   0b0010, 4, 13,12, self.LB_BITS, 0),   # MATCH_5N_3x0_SQ0   out.copybits(lastOut, masked, 12, 0)
    LookbackMask(  0b01101, 5, 14,16, self.LB_BITS, 0),   # MATCH_4N_4x0_SQ0   out.copybits(lastOut, masked, 16, 0)
    outputs op: <masked> <lookback> {0010|101010|01101|111010|000}

    When decompressing, outputs the specified previous word, with the masked bits replaced with the 'mask' value.
    """
    class Match(Operation.MatchBase):
        def __init__(self, op, m, lb):
            self.op = op
            self.m = m
            self.lb = lb
        def output(self, zipper, out):
            out.put(self.op.code, self.op.codelen)
            out.put(self.lb, zipper.LB_BITS)
            out.put(self.m, self.op.masklen)
            zipper.lastOut = self.lb-2**zipper.LB_BITS
        def __repr__(self):
            if self.op.masklen== 8: m = f"{self.m:02x}"
            elif self.op.masklen== 12: m = f"{self.m:03x}"
            elif self.op.masklen== 16: m = f"{self.m:04x}"
            return f"mask @{self.op.bitofs} m:{m}  lb={self.lb:03x}"

    def __init__(self, *args):
        super().__init__(*args[:-1])
        self.bitofs = args[-1]

    def matches(self, word, zipper, indata):
        mask = MASK(self.masklen)<<self.bitofs
        lbrange = 2**zipper.LB_BITS
        # 0 ..   pos-2-(2**LB-1)  ..   pos-2-0 [pos-1:word]
        for i in range(max(0, indata.pos-2-(lbrange-1)), indata.pos-1):
            if indata.data[i] & ~mask == word & ~mask:
                return self.Match(self, (word&mask)>>self.bitofs, lbrange-(indata.pos-1-i))

    def __repr__(self):
        return f"mask @{self.bitofs} m:{'n'*(self.masklen//4)}  lb=nnn"

class Mask(Operation):
    """
    Construct in one of the following ways:
    Mask(        0b0011010, 7,  6, 8, 0,16),              # MATCH_6N_2x4_SQ1   out.copybits(lastOut, masked,  8,16)   or END_BLOCK
    Mask(        0b1011010, 7,  5, 8, 0, 8),              # MATCH_6N_2x2_SQ1   out.copybits(lastOut, masked,  8, 8)
    Mask(            0b110, 3,  2, 8, 0, 0),              # MATCH_6N_2x0_SQ1   out.copybits(lastOut, masked,  8, 0)
    Mask(          0b11101, 5,  8,12, 0, 0),              # MATCH_5N_3x0_SQ1   out.copybits(lastOut, masked, 12, 0)
    Mask(         0b001010, 6, 10,16, 0, 0),              # MATCH_4N_4x0_SQ1   out.copybits(lastOut, masked, 16, 0)
    outputs op: <masked> {11101|011010|001010|1011010|110}

    When decompressing, repeats the most recent value, with the masked bits replaced.
    """
    class Match(Operation.MatchBase):
        def __init__(self, op, m):
            self.op = op
            self.m = m
        def output(self, zipper, out):
            out.put(self.op.code, self.op.codelen)
            out.put(self.m, self.op.masklen)
        def __repr__(self):
            if self.op.masklen== 8: m = f"{self.m:02x}"
            elif self.op.masklen== 12: m = f"{self.m:03x}"
            elif self.op.masklen== 16: m = f"{self.m:04x}"
            return f"mask @{self.op.bitofs} m:{m}"


    def __init__(self, *args):
        super().__init__(*args[:-1])
        self.bitofs = args[-1]

    def matches(self, word, zipper, indata):
        p = indata.pos-1+zipper.lastOut
        if p<0:
            return

        mask = MASK(self.masklen)<<self.bitofs
        if indata.data[p] & ~mask == word & ~mask:
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

    def output(self, out):
        out.put(self.code, self.codelen)
        out.put(0xFF, self.masklen)

    def __repr__(self):
        return f"break"

class Q6Zipper:
    def __init__(self, dict1, dict2, lookback=8):
        self.debug = False
        self.dict1 = dict1
        self.dict2 = dict2

        self.LB_BITS = lookback

        self.DICT1_BITS = bitlog(len(dict1))
        self.DICT2_BITS = bitlog(len(dict2))
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
            Dict(            0b100, 3,  4, 0, self.DICT1_BITS),   # DICT1_MATCH        out.addword(self.dict1[entry])
            Dict(           0b0101, 4,  7, 0, self.DICT2_BITS),   # DICT2_MATCH        out.addword(self.dict2[entry])
            Lookback(        0b001, 3,  3, 0, self.LB_BITS),      # MATCH_8N_SQ0       out.copyword(lastOut)
            Sequential(      0b111, 3,  1, 0,  0),                # MATCH_8N_SQ1       out.copyword(lastOut)
            Literal(         0b011, 3, 15, 0, 32),                # NO_MATCH           out.addword(masked)

            Mask(        0b0011010, 7,  6, 8, 0,16),              # MATCH_6N_2x4_SQ1   out.copybits(lastOut, masked,  8,16)   or END_BLOCK or END_BLOCK
            Mask(        0b1011010, 7,  5, 8, 0, 8),              # MATCH_6N_2x2_SQ1   out.copybits(lastOut, masked,  8, 8)
            Mask(            0b110, 3,  2, 8, 0, 0),              # MATCH_6N_2x0_SQ1   out.copybits(lastOut, masked,  8, 0)
            Mask(          0b11101, 5,  8,12, 0, 0),              # MATCH_5N_3x0_SQ1   out.copybits(lastOut, masked, 12, 0)
            Mask(         0b001010, 6, 10,16, 0, 0),              # MATCH_4N_4x0_SQ1   out.copybits(lastOut, masked, 16, 0)

            LookbackMask( 0b101010, 6, 12, 8, self.LB_BITS,16),   # MATCH_6N_2x4_SQ0   out.copybits(lastOut, masked,  8,16)
            LookbackMask( 0b111010, 6, 11, 8, self.LB_BITS, 8),   # MATCH_6N_2x2_SQ0   out.copybits(lastOut, masked,  8, 8)
            LookbackMask(    0b000, 3,  9, 8, self.LB_BITS, 0),   # MATCH_6N_2x0_SQ0   out.copybits(lastOut, masked,  8, 0)
            LookbackMask(   0b0010, 4, 13,12, self.LB_BITS, 0),   # MATCH_5N_3x0_SQ0   out.copybits(lastOut, masked, 12, 0)
            LookbackMask(  0b01101, 5, 14,16, self.LB_BITS, 0),   # MATCH_4N_4x0_SQ0   out.copybits(lastOut, masked, 16, 0)
        ]

        # sort by bit-size
        #self.ops = sorted(self.ops, key=lambda e:e.bitsize())
        self.ops = sorted(self.ops, key=lambda e:e.qcomorder)
        #for op in self.ops: print(f"{op.bitsize()} {op}")

        self.lastOut = -1    # the compressor state.

        self.breakpos0 = self.breakpos1 = None

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
        sortedxref = list(sorted(xref.items(), key=lambda kv: (kv[1], kv[0])))
        self.dict1 = [kv[0] for kv in sortedxref[:2**self.DICT1_BITS]]
        sortedxref = sortedxref[2**self.DICT1_BITS:]
        self.dict2 = [kv[0] for kv in sortedxref[:2**self.DICT2_BITS]]

    def compress(self, data):
        inp = WordStreamReader(data)
        out = BitStreamWriter()
 
        while not inp.eof():
            word = inp.nextword()
 
            for op in self.ops:
                if m := op.matches(word, self, inp):
                    m.output(self, out)
                    if self.debug:
                        print(f"    [{inp.pos:4x}] {len(out.data):4x}:{out.bitpos:2d}  {word:08x} ({self.lastOut:3d}) {m}")
                    break
            if self.needbreak(inp, out):
                op = Break()
                op.output(out)

                if self.debug:
                    print(f"    [{inp.pos:4x}] {len(out.data):4x}:{out.bitpos:2d}  {word:08x} ({self.lastOut:3d}) {op}")

        # the final break
        op = Break()
        op.output(out)
        out.flush()

        return out.data
 
    def needbreak(self, inp, out):
        if self.breakpos0 == inp.pos:
            self.breakpos0 = None
            return True
        if self.breakpos1 == inp.pos:
            self.breakpos1 = None
            return True

def main():
    parser = argparse.ArgumentParser(description='Compress data using q6zip compression')
    parser.add_argument('--offset', '-o', help='Which section to compress', type=str, default='0')
    parser.add_argument('--length', '-l', help='how many bytes to compress', type=str, default='0x1000')
    parser.add_argument('--dict1', help='offset:length to dict1', type=str, default='4:0x1000')
    parser.add_argument('--dict2', help='offset:length to dict2', type=str, default='0x1004:0x10000')
    parser.add_argument('--dictfile', help='load dict from', type=str)
    parser.add_argument('--breakpos0', help='load dict from', type=str)
    parser.add_argument('--breakpos1', help='load dict from', type=str)
    parser.add_argument('--debug', action='store_true', help="show all compression opcodes")

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
        args.dict1 = int(m[1],0), int(m[2],0)
    if m := re.match(r'(\w+):(\w+)', args.dict2):
        args.dict2 = int(m[1],0), int(m[2],0)

    with open(args.dictfile, "rb") as fh:
        fh.seek(args.dict1[0])
        dict1 = fh.read(args.dict1[1])
        dict1 = struct.unpack(f"<{len(dict1)//4}L", dict1)

        fh.seek(args.dict2[0])
        dict2 = fh.read(args.dict2[1])
        dict2 = struct.unpack(f"<{len(dict2)//4}L", dict2)
        
    with open(args.srcfile, "rb") as fh:
        fh.seek(args.offset)
        data = fh.read(args.length)

        data = struct.unpack(f"<{len(data)//4}L", data)

        C = Q6Zipper(dict1, dict2)
        C.debug = args.debug

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

