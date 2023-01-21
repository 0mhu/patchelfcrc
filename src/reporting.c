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
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

static bool global_verbosity_state = false;
static bool reporting_use_color = false;

#define COLOR_RESET "\e[0m"

#define COLOR_BOLD_RED "\e[31;1m"
#define COLOR_RED "\e[31m"

#define COLOR_BOLD_YELLOW "\e[33;1m"
#define COLOR_YELLOW "\e[33m"


void print_err(const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);

	/* Set color */
	if (reporting_use_color)
		fprintf(stderr, COLOR_BOLD_RED "[ERR]" COLOR_RESET " " COLOR_RED);
	else
		fprintf(stderr, "[ERR] ");


	vfprintf(stderr, fmt, va);

	/* Reset color */
	if (reporting_use_color) {
		fprintf(stderr, COLOR_RESET);
	}

	va_end(va);
}

void print_warn(const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);

	/* Set color */
	if (reporting_use_color)
		fprintf(stderr, COLOR_BOLD_YELLOW "[WARN]" COLOR_RESET " " COLOR_YELLOW);
	else
		fprintf(stderr, "[WARN] ");


	vfprintf(stderr, fmt, va);

	/* Reset color */
	if (reporting_use_color) {
		fprintf(stderr, COLOR_RESET);
	}

	va_end(va);
}

void print_debug(const char *fmt, ...)
{
	va_list va;

	if (global_verbosity_state) {
		va_start(va, fmt);
		(void)vprintf(fmt, va);
		va_end(va);
	}
}

void reporting_enable_verbose(bool state)
{
	global_verbosity_state = state;
}

bool reporting_get_verbosity(void)
{
	return global_verbosity_state;
}

/**
 * @brief Check whether stderr supports colors.
 * @note This function checks for a tty and the TERM environment variable. It has to contain "xterm".
 * @return true if colors are supported
 * @return false if no colors should be used
 */
static bool stderr_supports_colors(void)
{
	const char *env_var;
	const char *tmp;

	if (isatty(2) != 1)
		return false;

	env_var = getenv("TERM");
	if (!env_var)
		return false;

	tmp = strstr(env_var, "xterm");
	if (!tmp)
		return false;

	return true;
}

void reporting_init(enum reporting_color_mode mode)
{
	switch (mode) {
	case COLOR_MODE_COLOR:
		reporting_use_color = true;
		break;
	case COLOR_MODE_COLOR_OFF:
		reporting_use_color = false;
		break;
	default: /* Auto detect case and invalid settings */
		reporting_use_color = stderr_supports_colors();
		break;
	}
}
