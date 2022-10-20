#ifndef _ELFPATCH_H_
#define _ELFPATCH_H_

#include <stdint.h>
#include <patchelfcrc/crc.h>
#include <stdbool.h>

typedef struct elfpatch elfpatch_handle_t;

enum granularity {
    GRANULARITY_BYTE = 8,
    GRANULARITY_16BIT = 16,
    GRANULARITY_32BIT = 32,
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

#endif /* _ELFPATCH_H_ */
