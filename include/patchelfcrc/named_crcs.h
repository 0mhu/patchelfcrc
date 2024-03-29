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

#ifndef _NAMED_CRCS_H_
#define _NAMED_CRCS_H_

#include <stdint.h>
#include <stdbool.h>
#include <patchelfcrc/crc.h>

struct named_crc {
    const char *name;
    struct crc_settings settings;
};

const struct named_crc *reverse_lookup_named_crc(const struct crc_settings *settings);

const struct named_crc *lookup_named_crc(const char *name);

void list_predefined_crcs(void);

#endif /* _NAMED_CRCS_H_ */
