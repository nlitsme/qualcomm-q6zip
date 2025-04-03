
This tool uses `libclade.so` from the hexagon sdk.

## building

Build requires gnumake and cmake.
Specify the path to your hexagontools directory like this:

    make HEXAGONTOOLS=..../HEXAGON_Tools/8.7.06/Tools

## usage

    Usage: cladetool [options] filename
      --dictbytesize SIZE  - default: 0x2000
      --ndicts COUNT       - default: 3
      --dictofs OFS        - default: end-0x6040
      --wordsize N         - default: 1
      -o,--dataofs         - default: 0
      -l,--datasize        - default: 0x1000
      -v                   - show trace information

## example

    ./build/cladetool -l 64 ../samples/clade-barbet-tq2a.bin

    data: 545c0a5a80c500787c43025a12c06070924f0c5a804012b0822a01283242035aab00b0702e720a5a13c090916850005a00d300f505c012a12240909110c00224

