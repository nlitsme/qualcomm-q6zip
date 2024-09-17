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
  Type   Offset VirtAddr PhysAddr  FileSiz   MemSiz Flg 
...
  LOAD  1b9d000 859ff000 859ff000    7a1f5    7a1f5 R   --  zlibcomp    overlay_mem_dump ro_fatal
  LOAD  1c18000 85a7a000 85a7a000   9be000   9be000 R   --  q6zipped    .candidate_compress_section       | va=d0000000
  LOAD  25d7000 86439000 86439000    14000    14000 RW  --  deltacomped .rw_candidate_compress_section    | va=d104b000
  LOAD  25ec000 8644e000 8644e000    80000    80000 RWE --  
  LOAD  266d000 864cf000 864cf000   16dc50   16dc50 RW  --  QSR_STRING                                    | va=d4080000
  LOAD  27db000 8663d000 8663d000    00000  13c3000 RW  --  
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
python3 q6unzip.py -o 0x85a7a000 --dump --skipheader 0x0f15 mdm.elf
python3 deltauncomp.py -o 0x86439000 --dump mdm.elf

python3 q6unzip.py -o 0x85a7a000 --output q6zip.bin --skipheader 0x0f15 mdm.elf
python3 deltauncomp.py -o 0x86439000 --output delta.bin mdm.elf
```


## uncompressed location

The deltacomp and q6zip decompressors decompress data into a memory section not mentioned in the ELF header.
The pointers look like this in memory, so you can find them by looking for the addresses of the program sections:

```
virtaddr fileofs
8450BB00 01aadb00 .long 0xd0000000   << q6zip decompressed data+code
8450BB04 01aadb04 .long 0xd104b000   << end of q6zip decompressed data+code
8450BB08 01aadb08 .long 0x85a7a000   << q6zip compressed data
8450BB0c 01aadb0c .long 0x86438000   << end of q6zip compressed data

8450BB10 01aadb10 .long 0xd104b000   << delta decompressed data
8450BB14 01aadb14 .long 0xd14dc000   << end of delta decompressed data
8450BB18 01aadb18 .long 0x86439000   << delta compressed data
8450BB1c 01aadb1c .long 0x8644d000   << end of delta compressed data

8450BB20 01aadb20 .ascii "02.01.09", 0
```


# Author

Willem Hengeveld <itsme@xs4all.nl>

