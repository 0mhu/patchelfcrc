/*
 * This file is part of patchelfcrc.
 * Copyright (c) 2022 Mario Hüttel.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 only.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file elfpatch.h
 * @brief Header for ELF Patching Class
 */

#ifndef _ELFPATCH_H_
#define _ELFPATCH_H_

#include <stdint.h>
#include <patchelfcrc/crc.h>
#include <stdbool.h>
#include <linklist-lib/singly-linked-list.h>
#include <patchelfcrc/crc-datatypes.h>

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

elfpatch_handle_t *elf_patch_open(const char *path, bool readonly, bool expect_little_endian);

/**
 * @brief Check if a section is present in file
 * @param section Section name
 * @return 0 if present. Else -1. -1001 in case of pointer error
 */
int elf_patch_check_for_section(elfpatch_handle_t *ep, const char *section);

/**
 * @brief Get bit size of opened elf file
 * @param ep Elfpath handle
 * @return positive: Bits of ELF file. Either 32 or 64
 * @return negative, if error
 */
int elf_patch_get_bits(elfpatch_handle_t *ep);

/**
 * @brief Get VMA, LMA and size of section
 * @param ep Elfpatch handle
 * @param[in] section section name
 * @param[out] vma Virtual Memory Address. May be NULL.
 * @param[out] lma Load memory address. May be NULL.
 * @param[out] len Size of section in bytes. May be NULL.
 * @return 0 if successful
 * @return -1 if section is not found
 * @return -1000 and below: Parameter error.
 */
int elf_patch_get_section_address(elfpatch_handle_t *ep, const char *section,
                                  uint64_t *vma, uint64_t *lma, uint64_t *len);

/**
 * @brief Compute CRC over a section in an ELF file
 * @param ep Elf patch object
 * @param section Section name
 * @param[out] crc CRC output
 * @param granularity CRC calculation granularity
 * @param little_endian memory layout is little endian
 * @return 0 if successful
 * @return negative if error
 */
int elf_patch_compute_crc_over_section(elfpatch_handle_t *ep, const char *section, struct crc_calc *crc,
                                       enum granularity granularity, bool little_endian);

void elf_patch_close_and_free(elfpatch_handle_t *ep);

int elf_patch_write_crcs_to_section(elfpatch_handle_t *ep, const char *output_sec_name,
                    const struct crc_import_data *crc_data, bool use_vma,
                    uint32_t start_magic, uint32_t end_magic,
                    bool check_start_magic, bool check_end_magic,
                    enum crc_format format, bool little_endian);
#endif /* _ELFPATCH_H_ */
