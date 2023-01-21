% patchelfcrc(1) !version!
% Mario Huettel
% October 2022

# NAME
**patchelfcrc** - Patch CRC checksums into ELF files

# SYNOPSYS
**patchelfcrc** [**-lrv?V**] [**-g** *GRANULARITY*] [**-p** *POLYNOMIAL*] [**-s** *STARTVALUE*]
[**-x** *XORVAL*] [**-F** *FORMAT*] [**-O** *OUTPUTSECTION*] [**-S** *SEC*]
[**\--granularity**=*GRANULARITY*] [**\--little-endian**] [**\--dry-run**] [**\--xsd**]
[**\--poly**=*POLYNOMIAL*] [**\--reversed**] [**\--start-value**=*STARTVALUE*]
[**--verbose**] [**\--xor-out**=*XORVAL*] [**\--end-magic**=*MAGIC*]
[**\--crc-format**=*FORMAT*] [**\--use-vma**] [**\--list-crcs**] [**\--output-section**=*OUTPUTSECTION*]
[**\--export**=*XMLFILE*] [**\--import**=*XMLFILE*]
[**\--start-magic**=*MAGIC*] [**\--section**=*SECTION*] [**\--help**] [**\--usage**]
[**\--version**] *ELF*

# DESCRIPTION
**patchelfcrc** reads in sections of an *ELF* file and computes CRC checksums over the data. The calculated CRCs are placed in an output section of the *ELFFILE*. The output section must already exist inside the *ELF* file and must be big enough to hold all generated CRC checksums.

**patchelfcrc** supports multiple predefined CRCs as well as custom polynomials.

# OPTIONS
**-h**, **\--help**
: Display help

**\--usage**
: Display usage information

**-p** *POLYNOMIAL*, **\--polynomial**=*POLYNOMIAL*
: Polynomial to use for CRC calculation. For a n bit wide CRC supply a number with n+1 bits and the MSB set. Alternatively, a predifined name can be supplied. See **\--list-crcs** for details. At maximum a 32 bit wide CRC can be calculated. If nothing is given, crc-32-mpeg is used.

**-s** *STARTVALUE*, **\--start-value**=*STARTVALUE*
: Start value to preload CRC register with. This value is XORed with the *XORVAL* (see option **-x**).

**-x** *XORVAL*, **\--xor-value**=*XORVAL*
: XOR Value applied to initial start value (**-s**) and to the final CRC result.

**-r**, **\--reversed**
: Use bitreversed CRC. This is not implemented yet!

**-g** *GRANULARITY*, **\--granularity**=*GRANULARITY*
: CRC calculation granularity. This has no effect if big endian layout is used. For little endian layout, it specifies the sizes of the individual elements the CRC is computed over. 

: *GRANULARITY* = [word | halfword | byte]. Defaults to byte.

**-l**, **\--little-endian**
: The memory layout of the *ELFFILE* is in little-endian format.

**-F** *FORMAT*, **\--crc-format**=*FORMAT*
: Output format to place in output section. Options for *FORMAT* are *bare* or *struct*

**--use_vma**
: Use the virtual memory address (VMA) instead of the load memory address (LMA) for the address fields in the struct output. This option is only considered if the format is *struct*

**--start-magic**=*MAGIC*, **--endmagic**=*MAGIC*
: *MAGIC* numbers (32 bit unsigned) that are expected to be found at the start and the end of the given output section. This serves as safety guard against accidental corruption of the output file. *It is highly recommended to use these options*.

**--export**=*XMLFILE*
: Export the calculated files to an XML file *XMLFILE*.

**--import**=*XMLFILE*
: Import the CRCs from an XML file *XMLFILE* and do not caclulate anything in the given *ELF*

**--help**, **-h**, **-?**
: Print help.

**\--dry-run**
: Dry run. Do all calculations but do not write changes to file. *ELF* file will only be opened readonly. This mode implicitly activates the verbose output

**-v**, **\--verbose**
: Activate verbose output

**-V**, **\--version**
: Print version number

**\--list-crcs**
: List the possible predefined CRCs

**\--xsd**
: Print the XSD file used to validate the XML import to stdout

**--usage**
: Print usage hints on command line options.

**--no-color**
: Force output on stdout and stderr to be pure text without color codes.

# EXAMPLES

**patchelfcrc** --list-crcs

| Name             | Polynomial  | Reversed | Start Value | Output XOR |
|------------------|-------------|----------|-------------|------------|
| crc-8            | 0x107       | no       | 0x0         | 0x0        |
| crc-8-darc       | 0x139       | yes      | 0x0         | 0x0        |
| crc-8-i-code     | 0x11d       | no       | 0xfd        | 0x0        |
| crc-8-itu        | 0x107       | no       | 0x55        | 0x55       |
| crc-8-maxim      | 0x131       | yes      | 0x0         | 0x0        |
| crc-8-rohc       | 0x107       | yes      | 0xff        | 0x0        |
| crc-8-wcdma      | 0x19b       | yes      | 0x0         | 0x0        |
| crc-16           | 0x18005     | yes      | 0x0         | 0x0        |
| crc-16-buypass   | 0x18005     | no       | 0x0         | 0x0        |
| crc-16-dds-110   | 0x18005     | no       | 0x800d      | 0x0        |
| crc-16-dect      | 0x10589     | no       | 0x1         | 0x1        |
| crc-16-dnp       | 0x13d65     | yes      | 0xffff      | 0xffff     |
| crc-16-en-13757  | 0x13d65     | no       | 0xffff      | 0xffff     |
| crc-16-genibus   | 0x11021     | no       | 0x0         | 0xffff     |
| crc-16-maxim     | 0x18005     | yes      | 0xffff      | 0xffff     |
| crc-16-mcrf4xx   | 0x11021     | yes      | 0xffff      | 0x0        |
| crc-16-riello    | 0x11021     | yes      | 0x554d      | 0x0        |
| crc-16-t10-dif   | 0x18bb7     | no       | 0x0         | 0x0        |
| crc-16-teledisk  | 0x1a097     | no       | 0x0         | 0x0        |
| crc-16-usb       | 0x18005     | yes      | 0x0         | 0xffff     |
| x-25             | 0x11021     | yes      | 0x0         | 0xffff     |
| xmodem           | 0x11021     | no       | 0x0         | 0x0        |
| modbus           | 0x18005     | yes      | 0xffff      | 0x0        |
| kermit           | 0x11021     | yes      | 0x0         | 0x0        |
| crc-ccitt-false  | 0x11021     | no       | 0xffff      | 0x0        |
| crc-aug-ccitt    | 0x11021     | no       | 0x1d0f      | 0x0        |
| crc-24           | 0x1864cfb   | no       | 0xb704ce    | 0x0        |
| crc-24-flexray-a | 0x15d6dcb   | no       | 0xfedcba    | 0x0        |
| crc-24-flexray-b | 0x15d6dcb   | no       | 0xabcdef    | 0x0        |
| crc-32           | 0x104c11db7 | yes      | 0x0         | 0xffffffff |
| crc-32-bzip2     | 0x104c11db7 | no       | 0x0         | 0xffffffff |
| crc-32c          | 0x11edc6f41 | yes      | 0x0         | 0xffffffff |
| crc-32d          | 0x1a833982b | yes      | 0x0         | 0xffffffff |
| crc-32-mpeg      | 0x104c11db7 | no       | 0xffffffff  | 0x0        |
| posix            | 0x104c11db7 | no       | 0xffffffff  | 0xffffffff |
| crc-32q          | 0x1814141ab | no       | 0x0         | 0x0        |
| jamcrc           | 0x104c11db7 | yes      | 0xffffffff  | 0x0        |
| xfer             | 0x1000000af | no       | 0x0         | 0x0        |

**patchelfcrc** -l -g word --start-magic=0x12345678 --end-magic=0x8754321 -p crc-32-mpeg -f bare -O .outputsection -S .text executable.elf
: Calculate the CRC over *.text* section and place the result in the *.outputsection* section.
The output sections start and end are checked for the given magic numbers in order to assure correct memory layout.
*CRC-32-MPEG* is used as CRC algorothm.
The memory is interpreted as *little endian* and the CRC calculation granularity is a 32 bit *word*.

# BUGS
None
