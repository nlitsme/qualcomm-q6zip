from dataclasses import dataclass
from abc import ABC, abstractmethod
import struct
"""
Tool for decompressing q6zip compressed CODE sections.

Author: Willem Hengeveld <itsme@gsmk.de>
"""

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
        def decode(self, zipper, words) -> None:
            """ decodes this operation into a decompressed word """
            ...

        def isbreak(self):
            """ only true for the Break operation """
            return False

    @abstractmethod
    def matches(self, word, zipper, words) -> MatchBase:
        """ returns a MatchBase subclass when the word matches this operation """
        ...

    @abstractmethod
    def read(self, bits) -> MatchBase:
        """ decodes the parameters for this operation, and returns the result in as Match(Base) subclass """
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
        def decode(self, zipper, words):
            words.copyword(zipper.lastOut)
        def __repr__(self):
            return f"seq"

    def matches(self, word, zipper, words):
        p = words.pos-1+zipper.lastOut
        if p>=0 and words.data[p] == word:
            return self.Match(self)

    def read(self, bits):
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
        def decode(self, zipper, words):
            # update lastOut
            zipper.lastOut = self.lb-2**zipper.LB_BITS
            words.copyword(zipper.lastOut)
        def __repr__(self):
            return f"lookback  lb={self.lb:03x}"

    def matches(self, word, zipper, words):
        lbrange = 2**zipper.LB_BITS
        i = words.findlookback(word, 0, lbrange)
        if i is not None:
            return self.Match(self, i)

    def read(self, bits):
        return self.Match(self, bits.get(self.arglen))

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
        def decode(self, zipper, words):
            d = zipper.getdict(self.op.arglen)
            words.addword(d[self.ent])
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

    def read(self, bits):
        return self.Match(self, bits.get(self.arglen))

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
        def decode(self, zipper, words):
            words.addword(self.w)
        def __repr__(self):
            return f"lit {self.w:08x}"

    def matches(self, word, zipper, words):
        return self.Match(self, word)

    def read(self, bits):
        return self.Match(self, bits.get(32))

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
        def decode(self, zipper, words):
            # update lastOut
            zipper.lastOut = self.lb-2**zipper.LB_BITS
            words.copybits(zipper.lastOut, self.m, self.op.masklen, self.op.bitofs)
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

    def read(self, bits):
        lb = bits.get(self.arglen)
        masked = bits.get(self.masklen)
        return self.Match(self, masked, lb)

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
        def decode(self, zipper, words):
            words.copybits(zipper.lastOut, self.m, self.op.masklen, self.op.bitofs)
        def __repr__(self):
            if self.isbreak():
                return "break"
            if self.op.masklen== 8: m = f"{self.m:02x}"
            elif self.op.masklen== 12: m = f"{self.m:03x}"
            elif self.op.masklen== 16: m = f"{self.m:04x}"

            return f"mask @{self.op.bitofs} m:{m}"
        def isbreak(self):
            return self.op.masklen==8 and self.op.bitofs==16 and self.m == 0xff

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

    def read(self, bits):
        masked = bits.get(self.masklen)
        return self.Match(self, masked)

    def __repr__(self):
        return f"mask @{self.bitofs} m:{'n'*(self.masklen//4)}"


class Q6Unzipper:
    """
    Decompresses data encoded using the following bit packed format:

    The data is packed with a variable length opcode, listed in the table below.
    Read the opcodes from right-to-left.

               <entry1:10>      100   DICT1_MATCH       dict1 nnn                .addword(self.dict1[entry])
               <entry2:14>     0101   DICT2_MATCH       dict1 nnnn               .addword(self.dict2[entry])
               <dword:32>       011   NO_MATCH          lit nnnnnnnn             .addword(masked)
                                                                                 
                                111   MATCH_8N_SQ1      seq                      .copyword(lastOut)
   <masked:8>               0011010   MATCH_6N_2x4_SQ1  mask @16 m:nn            .copybits(lastOut, masked, 8, 16)   or END_BLOCK
   <masked:8>               1011010   MATCH_6N_2x2_SQ1  mask @8 m:nn             .copybits(lastOut, masked, 8, 8)
   <masked:8>                   110   MATCH_6N_2x0_SQ1  mask @0 m:nn             .copybits(lastOut, masked, 8, 0)
   <masked:12>                11101   MATCH_5N_3x0_SQ1  mask @0 m:nnn            .copybits(lastOut, masked, 12, 0)
   <masked:16>               001010   MATCH_4N_4x0_SQ1  mask @0 m:nnnn           .copybits(lastOut, masked, 16, 0)

               <lastout:8>      001   MATCH_8N_SQ0      lookback  lb=nnn         .copyword(lastOut)
   <masked:8>  <lastout:8>   101010   MATCH_6N_2x4_SQ0  mask @16 m:nn  lb=nnn    .copybits(lastOut, masked, 8, 16)
   <masked:8>  <lastout:8>   111010   MATCH_6N_2x2_SQ0  mask @8 m:nn  lb=nnn     .copybits(lastOut, masked, 8, 8)
   <masked:8>  <lastout:8>      000   MATCH_6N_2x0_SQ0  mask @0 m:nn  lb=nnn     .copybits(lastOut, masked, 8, 0)
   <masked:12> <lastout:8>     0010   MATCH_5N_3x0_SQ0  mask @0 m:nnn  lb=nnn    .copybits(lastOut, masked, 12, 0)
   <masked:16> <lastout:8>    01101   MATCH_4N_4x0_SQ0  mask @0 m:nnnn  lb=nnn   .copybits(lastOut, masked, 16, 0)

    """
    def __init__(self, dict1, dict2, lookback=8):
        self.debug = False

        self.dict1 = dict1
        self.dict2 = dict2

        self.LB_BITS = lookback

        self.DICT1_BITS = bitlog(len(dict1))
        self.DICT2_BITS = bitlog(len(dict2))

        self.tree = self.buildtree([    #   code clen   #  m arg  [bitpos]
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
        ])

    def buildtree(self, ops):
        tree = []
        for o in ops:
            q = None
            p = tree
            for i in range(o.codelen):
                b = (o.code>>i)&1
                while len(p)<=b:
                    p.append([])
                q = p
                p = p[b]
            q[b] = o
        return tree

    def getdict(self, bits):
        if bits == self.DICT1_BITS: return self.dict1
        if bits == self.DICT2_BITS: return self.dict2

    def decompress(self, compressed, MAXOUT=0x400):
        """
        Decompresses data from a byte array `compressed`, returning the uncompressed data bytes.
        """
        bits = BitStreamReader(compressed)
        words = WordStreamWriter()

        #  this is the only state of the algorithm.
        #  always a negative number from -2**LB+1 .. -1
        #  it is stored in the bitstream as  2^LB + lastOut
        self.lastOut = -1

        if self.debug:
            def log(msg):
                word = words.data[-1] if words.data else 0
                print(f"    [{words.len():04x}] {word:08x} {bits.pos:4x}:{bits.bitpos:2x} ({self.lastOut:4d}) {msg}")

            print("    outofs  outdata  ofs:bit last action")
        else:
            def log(msg):
                pass

        try:
            p = self.tree
            while words.len() <= MAXOUT:
                b = bits.get(1)
                p = p[b]
                if type(p)!=list:
                    m = p.read(bits)
                    if not m.isbreak():
                        m.decode(self, words)
                    elif words.len() >= MAXOUT:
                        log(m)
                        break
                    log(m)

                    p = self.tree

        except EOFError:
            log("EOF")
        finally:
            log("done")

        return words.data


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
    elif not args.nooutput and not args.debug:
        import sys
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

