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


#ifndef _REPORTING_H_
#define _REPORTING_H_

#include <stdbool.h>

#define print_err(fmt, ...) fprintf(stderr, "[ERR] " fmt, ## __VA_ARGS__)
#define print_warn(fmt, ...) fprintf(stderr, "[WARN] " fmt, ## __VAR__ARGS__)

void print_debug(const char *fmt, ...);

void reporting_enable_verbose(void);

bool reporting_get_verbosity(void);

#endif /* _REPORTING_H_ */
