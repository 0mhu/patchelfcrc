/*
 * This file is part of patchelfcrc .
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

#ifndef _CRC_H_
#define _CRC_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

struct crc_settings {
    uint64_t polynomial;
    uint32_t xor;
    uint32_t start_value;
    bool rev;
};

struct crc_calc {
    struct crc_settings settings;
    uint32_t crc_val;
    uint32_t crc_mask;
    uint32_t crc_length;
    uint32_t *table;
};

int crc_len_from_poly(uint64_t polynomial);

void crc_init(struct crc_calc *crc, const struct crc_settings *settings);

void crc_reset(struct crc_calc *crc);

void crc_destroy(struct crc_calc *crc);

void crc_push_byte(struct crc_calc *crc, uint8_t b);

void crc_push_bytes(struct crc_calc *crc, const uint8_t *b, size_t len);

void crc_finish_calc(struct crc_calc *crc);

uint32_t crc_get_value(struct crc_calc *crc);

#endif /* _CRC_H_ */
