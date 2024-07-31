"""
Tool for compressing delta compressed DATA sections.

Author: Willem Hengeveld <itsme@gsmk.de>
"""
from __future__ import division, print_function
from dataclasses import dataclass
from abc import ABC, abstractmethod
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
    code : int
    anchorlen : int
    arglen : int

    @abstractmethod
    def matches(self, word, zipper, out) -> bool: ...

    def bitsize(self):
        return 2 + self.anchorlen + self.arglen

    class MatchBase:
        def __init__(self, op):
            self.op = op

        @abstractmethod
        def output(self, zipper, out) -> None: ...

class Anchor(Operation):
    # code: 01 <aa>
    class Match(Operation.MatchBase):
        def __init__(self, op, aa):
            self.op = op
            self.aa = aa
        def output(self, zipper, out):
            out.put(self.op.code, 2)
            out.put(self.aa, self.op.anchorlen)
        def __repr__(self):
            return f"{self.op.code:02b}:A={self.aa}"

    def matches(self, word, zipper, indata):
        for i in range(2**self.anchorlen):
            if zipper.anchor(i)==word:
                return self.Match(self, i)

class AnchorDelta(Operation):
    # code: 10 <aa> <delta>
    class Match(Operation.MatchBase):
        def __init__(self, op, aa, delta):
            self.op = op
            self.aa = aa
            self.delta = delta
        def output(self, zipper, out):
            out.put(self.op.code, 2)
            out.put(self.aa, self.op.anchorlen)
            out.put(self.delta, self.op.arglen)
            zipper.setanchor(self.aa, self.delta)
        def __repr__(self):
            return f"{self.op.code:02b}:A={self.aa}+D={self.delta:03x}"

    def matches(self, word, zipper, indata):
        mask = 2**32-2**self.arglen
        deltamask = 2**self.arglen-1
        for i in range(2**self.anchorlen):
            if zipper.anchor(i)&mask==word&mask:
                return self.Match(self, i, word&deltamask)

class Literal(Operation):
    # code: 11 <word>
    class Match(Operation.MatchBase):
        def __init__(self, op, w):
            self.op = op
            self.w = w 
            self.curanchor = None
        def output(self, zipper, out):
            out.put(self.op.code, 2)
            out.put(self.w, 32)
            zipper.addanchor(self.w)
            self.curanchor = zipper.curanchor
        def __repr__(self):
            return f"{self.op.code:02b}:L={self.w:08x} -> {self.curanchor}"

    def matches(self, word, zipper, indata):
        return self.Match(self, word)

class Zero(Operation):
    # code: 00
    class Match(Operation.MatchBase):
        def __init__(self, op):
            self.op = op
        def output(self, zipper, out):
            out.put(self.op.code, 2)
        def __repr__(self):
            return f"{self.op.code:02b}:Z"

    def matches(self, word, zipper, indata):
        if word==0:
            return self.Match(self)


class DeltaCompressor:
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

        self.ops = [
            Zero(0b00, 0, 0 ),
            Anchor(0b01, self.anchorbits, 0),
            AnchorDelta(0b10, self.anchorbits, self.deltabits),
            Literal(0b11, 0, 32),
        ]
        self.ops = sorted(self.ops, key=lambda e:e.bitsize())

        self.anchors = [0] * 2**self.anchorbits
        self.curanchor = len(self.anchors)-1

    def anchor(self, i):
        return self.anchors[i]
    #return self.anchors[(self.curanchor+i) % len(self.anchors)]
    def addanchor(self, w):
        self.curanchor = (self.curanchor+1) % len(self.anchors)
        self.anchors[self.curanchor] = w
    def setanchor(self, a, delta):
        self.anchors[a] = (self.anchors[a] & ~MASK(self.deltabits)) | delta


    def compress(self, data):
        inp = WordStreamReader(data)
        out = BitStreamWriter()
        
        a = ''
        while not inp.eof():
            a = "{}:[{}] - ".format(self.curanchor, ','.join(f"{_:08x}" for _ in self.anchors))
            word = inp.nextword()
        
            for op in self.ops:
                if m := op.matches(word, self, inp):
                    m.output(self, out)
                    if self.debug:
                        print(f"    [{inp.pos:4x}] {len(out.data):4x}:{out.bitpos:2d}  {word:08x} {a}{m}")
                    break
        
        out.flush()

        return out.data

def main():
    parser = argparse.ArgumentParser(description='Compress data using delta compression')
    parser.add_argument('--offset', '-o', help='Which section to compress', type=str, default='0')
    parser.add_argument('--length', '-l', help='how many bytes to compress', type=str, default='0x1000')
    parser.add_argument('--debug', action='store_true')

    parser.add_argument('file', help='Which file to process', type=str)
    args = parser.parse_args()

    if args.offset is not None:
        args.offset = int(args.offset, 0)
    if args.length is not None:
        args.length = int(args.length, 0)

    with open(args.file, "rb") as fh:
        fh.seek(args.offset)
        data = fh.read(args.length)

        data = struct.unpack(f"<{len(data)//4}L", data)

        C = DeltaCompressor()
        C.debug = args.debug
        res = C.compress(data)
    
    res = struct.pack(f"<{len(res)}L", *res)

    if not args.debug:
        print(res.hex())

if __name__=="__main__":
    main()

