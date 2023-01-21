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

/**
 * @brief Setting for reporting to console.
 */
enum reporting_color_mode {
    COLOR_MODE_DETECT, /**< @brief Automatically detect if tty. If tty, color is used */
    COLOR_MODE_COLOR, /**< @brief Force color mode on stderr */
    COLOR_MODE_COLOR_OFF, /**< @brief Force no color on stderr */
};

void print_err(const char *fmt, ...);

void print_warn(const char *fmt, ...);

void print_debug(const char *fmt, ...);

void reporting_enable_verbose(bool state);

bool reporting_get_verbosity(void);

void reporting_init(enum reporting_color_mode mode);

#endif /* _REPORTING_H_ */
