#ifndef _ELFPATCHCRC_XML_H_
#define _ELFPATCHCRC_XML_H_

#include <stdint.h>
#include <linklist-lib/singly-linked-list.h>
#include <patchelfcrc/crc.h>
#include <patchelfcrc/elfpatch.h>

void xml_init(void);

int xml_write_crcs_to_file(const char *path, const uint32_t *crcs, SlList *section_names,
               const struct crc_settings *crc_params, elfpatch_handle_t *ep);

#endif /* _ELFPATCHCRC_XML_H_ */
