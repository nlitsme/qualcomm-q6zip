from q6zip import Q6Zipper
import struct
import datawriter

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

def main():
    import argparse
    parser = argparse.ArgumentParser(description='create a q6zip compressed data section')
    parser.add_argument('--baseofs', '-o', help='target offset', type=str)
    parser.add_argument('--debug', action='store_true', help="show all compression opcodes")
    parser.add_argument('--skipheader', help='number of items with extra skip header', type=str)
    parser.add_argument('--qcomorder', action='store_true', help="prioritize opcodes in qualcomm order.")
    parser.add_argument('--output', type=str, help='where to save the result')
    parser.add_argument('--lookback', help='lookback depth', type=int, default=8)
    parser.add_argument('--dict1bits', help='dict1 size', type=int, default=10)
    parser.add_argument('--dict2bits', help='dict2 size', type=int, default=14)
    parser.add_argument('--pagesize', type=str, default='0x1000')

    parser.add_argument('srcfile', help='Which file to process', type=str)
    args = parser.parse_args()

    if args.pagesize is not None:
        args.pagesize = int(args.pagesize, 0)
    if args.baseofs is not None:
        args.baseofs = int(args.baseofs, 0)
    if args.skipheader is not None:
        args.skipheader = int(args.skipheader, 0)

    if args.baseofs is None:
        print("WARNING: no base offset specified")
        args.baseofs = 0x80000000

    # read uncompressed data

    with open(args.srcfile, "rb") as fh:
        data = fh.read()
    datawords = bytes2words(data)
    q6 = Q6Zipper(args)
    q6.makedict(datawords)

    pagewords = args.pagesize // 4
    # compress sections
    sections = []
    for i in range(len(datawords)//pagewords):
        q6.reset()
        if args.debug:
            print(f"[{i:04x}]")
        if args.skipheader is None or i<args.skipheader:
            meta, cdata = q6.compresswithbreaks(datawords[i*pagewords:(i+1)*pagewords])
            sections.append((meta, cdata))
        else:
            cdata = q6.compress(datawords[i*pagewords:(i+1)*pagewords])
            sections.append((None, cdata))

    ptrs = []
    o = args.baseofs
    o += 4
    o += 2**args.dict1bits * 4
    o += 2**args.dict2bits * 4
    o += len(sections) * 4
    for m, c in sections:
        ptrs.append(o)
        if m:
            o += 4*len(m)
        o += 4 * len(c)

    with open(args.output, "wb") as ofh:
        w = datawriter.new(ofh)
        # write hdr
        w.write16le(len(sections))
        w.write16le(0x0600)         # version
        # write dicts
        w.write(words2bytes(q6.dict1))
        w.write(words2bytes(q6.dict2))
        # write ptrlist
        w.write(words2bytes(ptrs))
        # write compressed data
        for m, c in sections:
            if m:
                w.write(words2bytes(m))
            w.write(words2bytes(c))


if __name__=="__main__":
    main()

