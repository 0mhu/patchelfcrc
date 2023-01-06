#ifndef _ELFPATCHCRC_DATATYPES_H_
#define _ELFPATCHCRC_DATATYPES_H_

#include <stdint.h>

struct crc_entry {
    char *name;
    uint64_t vma;
    uint64_t lma;
    uint64_t size;
    uint32_t crc;
};

struct crc_import_data {
    int elf_bits;
    struct crc_settings crc_config;
    SlList *crc_entries; /**< @brief linked list of @ref crc_entry structs */
};

#endif /* _ELFPATCHCRC_DATATYPES_H_ */
