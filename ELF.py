"""
ELF file manipulation.

Author: Willem Hengeveld <itsme@gsmk.de>
"""
import struct

class Reader:
    """
    Architecture dependent ELF header value reader
    """
    def __init__(self, fh):
        self.fh = fh
        self.setendianness("<")  # default: little-endian
        self.setintsize(4)

    def setendianness(self, e):
        self.endian = e

    def setintsize(self, n):
        if n==4:
            self.inttype = "L"
            self.intsize = 4
        elif n==8:
            self.inttype = "Q"
            self.intsize = 8
        else:
            raise Exception("elfreader: invalid intsize: %d" % n)
    def is32bit(self): return self.intsize==4
    def is64bit(self): return self.intsize==8

    def uint(self):
        return struct.unpack(self.endian + self.inttype, self.fh.read(self.intsize))[0]
    def byte(self):
        return struct.unpack("B", self.fh.read(1))[0]
    def uint16(self):
        return struct.unpack(self.endian + "H", self.fh.read(2))[0]
    def uint32(self):
        return struct.unpack(self.endian + "L", self.fh.read(4))[0]
    def uint64(self):
        return struct.unpack(self.endian + "Q", self.fh.read(8))[0]
    def string(self, size, encoding='utf-8'):
        return self.fh.read(size).decode(encoding)
    def bytes(self, size):
        return self.fh.read(size)
    def skip(self, size):
        self.fh.seek(size, 1)
    def setpos(self, pos):
        self.fh.seek(pos, 0)
    def tell(self):
        return self.fh.tell()

class Writer:
    """
    Architecture dependent ELF header value writer
    """
    def __init__(self, fh):
        self.fh = fh
        self.setendianness("<")  # default: little-endian
        self.setintsize(4)

    def setendianness(self, e):
        self.endian = e

    def setintsize(self, n):
        if n==4:
            self.inttype = "L"
            self.intsize = 4
        elif n==8:
            self.inttype = "Q"
            self.intsize = 8
        else:
            raise Exception("elfreader: invalid intsize: %d" % n)
    def is32bit(self): return self.intsize==4
    def is64bit(self): return self.intsize==8

    def uint(self, value):
        self.fh.write(struct.pack(self.endian + self.inttype, value))
    def byte(self, value):
        self.fh.write(struct.pack("B", value))
    def uint16(self, value):
        self.fh.write(struct.pack(self.endian + "H", value))
    def uint32(self, value):
        self.fh.write(struct.pack(self.endian + "L", value))
    def uint64(self, value):
        self.fh.write(struct.pack(self.endian + "Q", value))
    def string(self, txt, encoding='utf-8'):
        self.fh.write(txt.encode(encoding))
    def bytes(self, data):
        self.fh.write(data)
    def skip(self, size):
        self.fh.seek(size, 1)
    def setpos(self, pos):
        self.fh.seek(pos, 0)

def addconstants(prefix, lst):
    import inspect
    frame = inspect.currentframe().f_back.f_locals
    for i, name in enumerate(lst):
        frame[prefix+"_"+name] = i


addconstants("SEGTYP", "L4, AMSS, HASH, BOOT, L4BSP, SWAPPED, SWAPPOOL, PHDR".split(", "))
addconstants("ACCTYP", "RW, RO, ZI, UNUSED, SHARED".split(", "))

class Header:
    """
    parse / save an ELF header, including program and section headers.
    """
    class ProgramHeader:
        """
        parse / save an ELF program header

        -- 64 bit layout

        +00 dword type
        +04 dword flags
        +08 qword fileofs
        +10 qword vaddr
        +18 qword vaddr
        +20 qword filesize
        +28 qword memsize
        +30 qword align

        -- 32 bit layout

        +00 dword type
        +04 dword fileofs
        +08 dword vaddr
        +0c dword vaddr
        +10 dword filesize
        +14 dword memsize
        +18 dword flags
        +1c dword align

        """
        def parse(self, rd):
            self.type = rd.uint32()
            if rd.is64bit():
                self.flags = rd.uint32()

            self.fileoffset = rd.uint()
            self.vaddr = rd.uint()
            self.paddr = rd.uint()
            self.filesize = rd.uint()
            self.memsize = rd.uint()

            if rd.is32bit():
                self.flags = rd.uint32()

            self.align = rd.uint()

        def save(self, wr):
            wr.uint32(self.type)
            if wr.is64bit():
                wr.uint32(self.flags)
            wr.uint(self.fileoffset)
            wr.uint(self.vaddr)
            wr.uint(self.paddr)
            wr.uint(self.filesize)
            wr.uint(self.memsize)
            if wr.is32bit():
                wr.uint32(self.flags)
            wr.uint(self.align)

        @staticmethod
        def size(rd):
            return 8 + 6 * rd.intsize

        def flagstring(self):
            pool = self.has_pool_index()
            segtyp = self.segment_type()
            acctyp = self.access_type()
            pg = self.is_paged()

            pooled   = [ " ", "*" ]
            segtypes = [ "L4", "AMSS", "HASH", "BOOT", "L4BSP", "SWAPPED", "SWAPPOOL", "PHDR" ]
            acctypes = [ "RW", "RO", "ZI", "UNUSED", "SHARED", "acc5", "acc6", "acc7" ]
            paged    = [ "", "paged" ]

            return "%s%-8s %-6s%-5s" % ( pooled[pool], segtypes[segtyp], acctypes[acctyp], paged[pg] )
        def permstring(self):
            perms = [ "   ", "  E", " W ", " WE", "R  ", "R E", "RW ", "RWE" ]
            return perms[self.flags&7]

        def __repr__(self):
            return "%04x %08x %08x %08x %08x %08x %08x(%s) [%s] %04x" % (
                self.type, self.fileoffset or 0, self.vaddr, self.paddr, self.filesize, self.memsize, self.flags, self.flagstring(), self.permstring(), self.align)

        def has_pool_index(self):
            return (self.flags >> 27)&1 != 0

        def segment_type(self):
            return (self.flags >> 24)&7

        def access_type(self):
            return (self.flags >> 21)&7

        def is_paged(self):
            return (self.flags >> 20)&1 != 0

        def hasvaddr(self, vaddr):
            return 0 <= vaddr-self.vaddr < self.filesize
        def haspaddr(self, paddr):
            return 0 <= paddr-self.paddr < self.filesize
        def isvend(self, vaddr):
            return vaddr == self.vaddr+self.filesize
        def ispend(self, paddr):
            return paddr == self.paddr+self.filesize



    class SectionHeader:
        """
        parse / save an ELF section header
        """
        def parse(self, rd):
            self.off_name = rd.uint32()
            self.type = rd.uint32()
            self.flags = rd.uint()
            self.vaddr = rd.uint()
            self.fileoffset = rd.uint()
            self.size = rd.uint()
            self.link = rd.uint32()
            self.info = rd.uint32()
            self.addralign = rd.uint()
            self.entsize = rd.uint()

        def save(self, wr):
            wr.uint32(self.off_name)
            wr.uint32(self.type)
            wr.uint(self.flags)
            wr.uint(self.vaddr)
            wr.uint(self.fileoffset)
            wr.uint(self.size)
            wr.uint32(self.link)
            wr.uint32(self.info)
            wr.uint(self.addralign)
            wr.uint(self.entsize)

        @staticmethod
        def size(rd):
            return 16 + 6 * rd.intsize

        def __repr__(self):
            return "t:%d, f:0x%x, v:0x%08x, o:0x%08x, l=0x%06x, l:%d, i:%d, a:%d, e=%2d n:#%d" % (
            self.type,self.flags,self.vaddr,self.fileoffset,self.size,self.link,self.info,self.addralign,self.entsize,self.off_name)


    def __init__(self):
        self.sect = []
        self.pgm = []

    def parse(self, rd):
        self.filebase = rd.tell()
        magic = rd.bytes(4)              # 00
        if magic!=b'\x7fELF':
            raise Exception("invalid ELF magic")

        self.intsize = rd.byte()         # 04  1 = 32bit, 2 = 64bit
        rd.setintsize(4 * self.intsize)

        self.endianness = rd.byte()      # 05  1 = little, 2 = big endian
        rd.setendianness("<" if self.endianness==1 else ">")

        self.elfversion1 = rd.byte()     # 06
        self.abitype = rd.byte()         # 07  0=sysv, 3=linux, ...
        self.abiversion = rd.byte()      # 08
        self.padding = rd.bytes(7)       # 09
        self.filetype = rd.uint16()      # 10  1=reloc, 2=exec, 3=shared, 4=core
        self.machine = rd.uint16()       # 12  2=spart, 3=x86, 8=mips, 40=ARM, 50=ia64, 62=x64, 183=aarch64, 164=qdsp6
        self.elfversion = rd.uint32()    # 14
        self.entrypoint = rd.uint()      # 18
        self.phoff = rd.uint()           # 1c/20
        self.shoff = rd.uint()           # 20/28
        self.flags = rd.uint32()         # 24/30  for hexagon: contains cpu-subtype
        self.ehsize = rd.uint16()        # 28/34  size of this header
        phentsize = rd.uint16()          # 2a/36
        phnum = rd.uint16()              # 2c/38
        shentsize = rd.uint16()          # 2e/3a
        shnum = rd.uint16()              # 30/3c
        self.shstrndx = rd.uint16()      # 32/3e

        if phentsize != self.ProgramHeader.size(rd):
            print("WARNING: phentsize = %d, expected %d" % (phentsize, self.ProgramHeader.size(rd)))
        if shentsize != self.SectionHeader.size(rd):
            print("WARNING: shentsize = %d, expected %d" % (shentsize, self.SectionHeader.size(rd)))


        for _ in range(phnum):
            seg = self.ProgramHeader()
            rd.setpos(self.filebase + self.phoff + _ * phentsize)
            seg.parse(rd)
            self.pgm.append(seg)

        for _ in range(shnum):
            sect = self.SectionHeader()
            rd.setpos(self.filebase + self.shoff + _ * shentsize)
            sect.parse(rd)
            self.sect.append(sect)

    def virt2file(self, offset):
        seg = self.virtseg(offset)
        if not seg:
            print("ofs=%08x" % offset)
            raise Exception("invalid offset")
        return offset - seg.vaddr + seg.fileoffset

    def virtend(self, offset):
        seg = self.virtseg(offset)
        return seg.vaddr + seg.filesize

    def virtseg(self, vofs):
        # returns highest segment containing this address.
        # also returns segment for address just one beyond the last byte.
        found = None
        for seg in sorted(self.pgm, key=lambda x: x.vaddr):
            if seg.hasvaddr(vofs) or seg.isvend(vofs):
                found = seg
        return found

    def phys2file(self, offset):
        seg = self.physseg(offset)
        return offset - seg.paddr + seg.fileoffset

    def physend(self, offset):
        seg = self.physseg(offset)
        return seg.paddr + seg.filesize

    def physseg(self, pofs):
        # returns highest segment containing this address.
        # also returns segment for address just one beyond the last byte.
        for seg in sorted(self.pgm, key=lambda x: x.paddr):
            if seg.haspaddr(pofs) or seg.ispend(pofs):
                found = seg
        return found

    def save(self, fh):
        wr = Writer(fh)
        wr.setintsize(4 * self.intsize)
        wr.setendianness("<" if self.endianness==1 else ">")

        wr.bytes(b"\x7fELF")
        wr.byte(self.intsize)
        wr.byte(self.endianness)

        wr.byte(self.elfversion1)
        wr.byte(self.abitype)         # 0=sysv, 3=linux, ...
        wr.byte(self.abiversion)
        wr.bytes(b"\x00" * 7)
        wr.uint16(self.filetype)      #  1=reloc, 2=exec, 3=shared, 4=core
        wr.uint16(self.machine)       #  2=spart, 3=x86, 8=mips, 40=ARM, 50=ia64, 62=x64, 183=aarch64
        wr.uint32(self.elfversion)

        wr.uint(self.entrypoint)
        wr.uint(self.phoff)
        wr.uint(self.shoff)
        wr.uint32(self.flags)
        wr.uint16(self.ehsize)   # size of this header
        wr.uint16(self.ProgramHeader.size(wr))
        wr.uint16(len(self.pgm))
        wr.uint16(self.SectionHeader.size(wr))
        wr.uint16(len(self.sect))
        wr.uint16(self.shstrndx)

        wr.setpos(self.phoff)
        for seg in self.pgm:
            seg.save(wr)
        wr.setpos(self.shoff)
        for sect in self.sect:
            sect.save(wr)

    def recalcoffsets(self):
        # recalculate file offsets, taking into account sections which have grown/shrunk.

        filedelta = 0
        prevend = None

        for seg in sorted(self.pgm, key=lambda seg : seg.fileoffset):
            if prevend and seg.fileoffset <= prevend:
                seg.fileoffset = ((prevend+0x1000) // 0x1000) * 0x1000

            prevend = seg.fileoffset + seg.filesize

    def __repr__(self):
        return "ELF %d,%d,%d,%d,%d\n" % ( self.intsize, self.endianness, self.elfversion1, self.abitype, self.abiversion )   + \
                " ft:%d, m:0x%x, v:%d, ep=0x%x, ph=+0x%x, sh=+0x%x, fl=0x%x, ehsize=%d, str=0x%x\n" % ( self.filetype, self.machine, self.elfversion, self.entrypoint, self.phoff, self.shoff, self.flags, self.ehsize, self.shstrndx)   + \
                "\npgm:\n" + "\n".join(repr(_) for _ in self.pgm)   + \
                "\nsect:\n" + "\n".join(repr(_) for _ in self.sect)


def read(fh):
    """
    Create a ELF reader.
    """
    elf = Header()
    elf.parse(Reader(fh))

    return elf

