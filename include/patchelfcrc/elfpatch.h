#ifndef _ELFPATCH_H_
#define _ELFPATCH_H_

#include <stdint.h>
#include <patchelfcrc/crc.h>
#include <stdbool.h>
#include <linklist-lib/singly-linked-list.h>

typedef struct elfpatch elfpatch_handle_t;

enum granularity {
    GRANULARITY_BYTE = 8,
    GRANULARITY_16BIT = 16,
    GRANULARITY_32BIT = 32,
};

enum crc_format {
    FORMAT_BARE = 0,
    FORMAT_STRUCT,
};

elfpatch_handle_t *elf_patch_open(const char *path, bool readonly);

/**
 * @brief Check if a section is present in file
 * @param section Section name
 * @return 0 if present. Else -1. -1001 in case of pointer error
 */
int elf_patch_check_for_section(elfpatch_handle_t *ep, const char *section);

int elf_patch_compute_crc_over_section(elfpatch_handle_t *ep, const char *section, struct crc_calc *crc,
                                       enum granularity granularity, bool little_endian);

void elf_patch_close_and_free(elfpatch_handle_t *ep);

/**
 * @brief Write CRCs to output section. This will have no effect, if file is opened read onyl
 * @param ep Elf patch object
 * @param[in] section Section name to place CRCs in
 * @param[in] section_name_list The list of sections the data belongs to
 * @param[in] crcs CRCs. Must be of the same lenght as the \p section_name_list
 * @return 0 Success
 * @return -1000 Parameter error
 * @return -1 internal error
 */
int elf_patch_write_crcs_to_section(elfpatch_handle_t *ep, const char *section, const SlList *section_name_list,
                    const uint32_t *crcs, uint8_t crc_size_bits, uint32_t start_magic, uint32_t end_magic,
                    bool check_start_magic, bool check_end_magic, enum crc_format format, bool little_endian);
#endif /* _ELFPATCH_H_ */
