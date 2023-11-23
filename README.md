# q6unzip and deltauncomp

Hexagon based qualcomm firmware usually has two sections with compressed code and compressed data.

When you find one of the leaked qualcomm sources, this is handled by the `dlpager` kernel module.

| sectiontype | content | compression algorithm
|:----------- |:------- |:----------------------
|   rw        | data    | `deltaCompress` / `deltaUncompress`
|   rx        | code    | `q6zip_uncompress`

These algorithms have several pre-configured parameters, which may vary between firmware versions.
These parameters need to be guessed, or found by reverse engineering.

## q6zip parameters

 * dict1 size ( usually 10 bits )
 * dict2 size ( usually 15 bits )
 * lookback size ( usually 8 bits )
 * the number of entries with sub-indices

In most roms the q6zip section is divided in two parts, in the first, each entry is prefixed
with two 32 bit words, which indicates the compression state for four subpages.


## delta parameters

 * delta size ( usually 10 bits )
 * anchor size ( usually 2 bits )

# usage

First use `readelf -l rom.elf`  to find the likely offsets to the compressed sections.

Output will usually look like this:

```
Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
...
  LOAD           0x1e3b000 0x8597e000 0x8597e000 0xa0f000 0xa0f000 R   0x1000  << this is the q6zip section
  LOAD           0x284b000 0x8638e000 0x8638e000 0x14000 0x14000 RW  0x1000   << this is the deltacomp section
  LOAD           0x2860000 0x863a3000 0x863a3000 0x80000 0x80000 RWE 0x1000
  LOAD           0x28e1000 0x86424000 0x86424000 0xa2b0c 0xa2b0c RW  0x1000
  LOAD           0x2984000 0x864c7000 0x864c7000 0x00000 0x1539000 RW  0x1000
```

The deltacomp data looks something like this:

  - start at program section boundary
  - a dword with some size information
  - a list of pointers, for each page a pointer to the compressed data.
    This should be visually recognizable as a list of numerically similar numbers.
    Usually around 60 - 60 pointers.
  - followed by the compressed data.

The q6zip data looks something like this:

  - start at program section boundary
  - a dword with some size information
  - the two dictionaries, the first word usually is zero.
    The combined size is always:   2^a + 2^b,  with a != b, so a number with two bits set.
  - folloed by a large list (+- 4000) of data pointers.
  - followed by the ocmpressed data.
  - approx the first half of the compressed entries will start with byte 0xff, from this you may be able to find the 
    number to pass with the `--skipheader` argument.


Example usage:

```
python3 q6unzip.py -o 0x8597e000 --dump --skipheader 0x0f5d mdm.elf
python3 deltauncomp.py -o 0x8638E000 --dump mdm.elf

python3 q6unzip.py -o 0x8597e000 --output q6zip.bin --skipheader 0x0f5d mdm.elf
python3 deltauncomp.py -o 0x8638E000 --output delta.bin mdm.elf
```


# Author

Willem Hengeveld <itsme@xs4all.nl>

