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


#include <patchelfcrc/reporting.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>

static bool global_verbosity_state = false;

void print_debug(const char *fmt, ...)
{
	va_list va;

	if (global_verbosity_state) {
		va_start(va, fmt);
		(void)vprintf(fmt, va);
		va_end(va);
	}
}

void reporting_enable_verbose(void)
{
	global_verbosity_state = true;
}

bool reporting_get_verbosity(void)
{
	return global_verbosity_state;
}
