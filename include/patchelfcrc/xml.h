#ifndef _ELFPATCHCRC_XML_H_
#define _ELFPATCHCRC_XML_H_

#include <stdint.h>
#include <linklist-lib/singly-linked-list.h>
#include <patchelfcrc/crc.h>
#include <patchelfcrc/elfpatch.h>

struct xml_crc_entry {
    char *name;
    uint64_t vma;
    uint64_t lma;
    uint64_t size;
    uint32_t crc;
};

struct xml_crc_import {
    int elf_bits;
    struct crc_settings crc_config;
    SlList *xml_crc_entries; /**< @brief linked list of @ref xml_crc_entry structs */
};

void xml_init(void);

int xml_write_crcs_to_file(const char *path, const uint32_t *crcs, SlList *section_names,
               const struct crc_settings *crc_params, elfpatch_handle_t *ep);

/**
 * @brief xml_import_from_file Import from file
 * @param path Path to import from
 * @return Returns a newly allocated struct. Must be freed with @ref xml_crc_import_free
 * @return NULL in case of error
 */
struct xml_crc_import *xml_import_from_file(const char *path);

/**
 * @brief Fully free supplied import data
 * @param data Data to free
 */
void xml_crc_import_free(struct xml_crc_import *data);

/**
 * @brief Print XML XSD file to stdout
 */
void xml_print_xsd(void);

#endif /* _ELFPATCHCRC_XML_H_ */
