% patchelfcrc(1) 0.0.2
% Mario Huettel
% October 2022

# NAME
patchelfcrc - Patch CRC checksums into ELF files

# SYNOPSYS
**patchelfcrc** [*OPTIONS*] *ELFFILE*

# DESCRIPTION
**patchelfcrc** reads in sections of an *ELFFILE* and computes CRC checksums over the data. The calculated CRCs are placed in an output section of the *ELFFILE*. The output section must already exist inside the *ELFFILE* and must be big enough to hold all generated CRC checksums.

**patchelfcrc** supports multiple predefined CRCs as well as custom polynomials.

# OPTIONS
**-h**, **\--help**
: Display help

**\--usage**
: Display usage information

**-g** *GRANULARITY*, **\--granularity**=*GRANULARITY*
: CRC calculation granularity. This has no effect if big endian layout is used. For little endian layout, it specifies the sizes of the individual elements the CRC is computed over. 

: *GRANULARITY* = [word | halfword | byte]. Defaults to byte.

**-l**, **\--little-endian**
: The memory layout of the *ELFFILE* is in little-endian format.

**--start-magic**=*MAGIC*, **--endmagic**=*MAGIC*
: *MAGIC* numbers (32 bit unsigned) that are expected to be found at the start and the end of the given output section. This serves as safety guard against accidental corruption of the output file. *It is highly recommended to use these options*.

# BUGS
Currently, reversed CRC algorithms are not implemented.