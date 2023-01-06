#ifndef _ELFPATCHCRC_XML_H_
#define _ELFPATCHCRC_XML_H_

#include <linklist-lib/singly-linked-list.h>
#include <patchelfcrc/crc.h>
#include <patchelfcrc/crc-datatypes.h>

void xml_init(void);

int xml_write_crcs_to_file(const char *path, const struct crc_import_data *crc_data);

/**
 * @brief xml_import_from_file Import from file
 * @param path Path to import from
 * @return Returns a newly allocated struct. Must be freed with @ref xml_crc_import_free
 * @return NULL in case of error
 */
struct crc_import_data *xml_import_from_file(const char *path);

/**
 * @brief Fully free supplied import data
 * @param data Data to free
 */
void xml_crc_import_free(struct crc_import_data *data);

/**
 * @brief Print XML XSD file to stdout
 */
void xml_print_xsd(void);

struct crc_import_data *xml_crc_import_alloc(void);

#endif /* _ELFPATCHCRC_XML_H_ */
