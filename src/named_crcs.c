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

#include <patchelfcrc/named_crcs.h>
#include <stddef.h>
#include <string.h>
#include <fort.h>
#include <stdio.h>

#define NAMED_CRC(crc_name, poly, reverse, init, outxor) { \
	.name = crc_name, \
	.settings = { \
		.polynomial = poly, \
		.xor = outxor, \
		.start_value = init, \
		.rev = reverse \
} }

const struct named_crc predefined_crc_table[] = {
	NAMED_CRC("crc-8", 0x107, false, 0x00, 0x00),
	NAMED_CRC("crc-8-darc", 0x139, true, 0x00, 0x00),
	NAMED_CRC("crc-8-i-code", 0x11D, false, 0xFD, 0x00),
	NAMED_CRC("crc-8-itu", 0x107, false, 0x55, 0x55),
	NAMED_CRC("crc-8-maxim", 0x131, true, 0x00, 0x00),
	NAMED_CRC("crc-8-rohc", 0x107, true, 0xFF, 0x00),
	NAMED_CRC("crc-8-wcdma", 0x19B, true, 0x00, 0x00),
	NAMED_CRC("crc-16", 0x18005, true, 0x0000, 0x0000),
	NAMED_CRC("crc-16-buypass", 0x18005, false, 0x0000, 0x0000),
	NAMED_CRC("crc-16-dds-110", 0x18005, false, 0x800D, 0x0000),
	NAMED_CRC("crc-16-dect", 0x10589, false, 0x0001, 0x0001),
	NAMED_CRC("crc-16-dnp", 0x13D65, true, 0xFFFF, 0xFFFF),
	NAMED_CRC("crc-16-en-13757", 0x13D65, false, 0xFFFF, 0xFFFF),
	NAMED_CRC("crc-16-genibus", 0x11021, false, 0x0000, 0xFFFF),
	NAMED_CRC("crc-16-maxim", 0x18005, true, 0xFFFF, 0xFFFF),
	NAMED_CRC("crc-16-mcrf4xx", 0x11021, true, 0xFFFF, 0x0000),
	NAMED_CRC("crc-16-riello", 0x11021, true, 0x554D, 0x0000),
	NAMED_CRC("crc-16-t10-dif", 0x18BB7, false, 0x0000, 0x0000),
	NAMED_CRC("crc-16-teledisk", 0x1A097, false, 0x0000, 0x0000),
	NAMED_CRC("crc-16-usb", 0x18005, true, 0x0000, 0xFFFF),
	NAMED_CRC("x-25", 0x11021, true, 0x0000, 0xFFFF),
	NAMED_CRC("xmodem", 0x11021, false, 0x0000, 0x0000),
	NAMED_CRC("modbus", 0x18005, true, 0xFFFF, 0x0000),
	NAMED_CRC("kermit", 0x11021, true, 0x0000, 0x0000),
	NAMED_CRC("crc-ccitt-false", 0x11021, false, 0xFFFF, 0x0000),
	NAMED_CRC("crc-aug-ccitt", 0x11021, false, 0x1D0F, 0x0000),
	NAMED_CRC("crc-24", 0x1864CFB, false, 0xB704CE, 0x000000),
	NAMED_CRC("crc-24-flexray-a", 0x15D6DCB, false, 0xFEDCBA, 0x000000),
	NAMED_CRC("crc-24-flexray-b", 0x15D6DCB, false, 0xABCDEF, 0x000000),
	NAMED_CRC("crc-32", 0x104C11DB7, true, 0x00000000, 0xFFFFFFFF),
	NAMED_CRC("crc-32-bzip2", 0x104C11DB7, false, 0x00000000, 0xFFFFFFFF),
	NAMED_CRC("crc-32c", 0x11EDC6F41, true, 0x00000000, 0xFFFFFFFF),
	NAMED_CRC("crc-32d", 0x1A833982B, true, 0x00000000, 0xFFFFFFFF),
	NAMED_CRC("crc-32-mpeg", 0x104C11DB7, false, 0xFFFFFFFF, 0x00000000),
	NAMED_CRC("posix", 0x104C11DB7, false, 0xFFFFFFFF, 0xFFFFFFFF),
	NAMED_CRC("crc-32q", 0x1814141AB, false, 0x00000000, 0x00000000),
	NAMED_CRC("jamcrc", 0x104C11DB7, true, 0xFFFFFFFF, 0x00000000),
	NAMED_CRC("xfer", 0x1000000AF, false, 0x00000000, 0x00000000),
	/* SENTINEL */
	{ .name = NULL, .settings = {0, 0, 0, false} },
};

const struct named_crc *reverse_lookup_named_crc(const struct crc_settings *settings)
{
	const struct named_crc *iter;
	const struct named_crc *found = NULL;

	for (iter = predefined_crc_table; iter->name; iter++) {
		if (iter->settings.polynomial == settings->polynomial &&
		iter->settings.rev == settings->rev &&
		iter->settings.start_value == settings->start_value &&
		iter->settings.xor == settings->xor) {
			found = iter;
			break;
		}
	}

	return found;
}

const struct named_crc *lookup_named_crc(const char *name)
{
	const struct named_crc *iter;
	const struct named_crc *found = NULL;

	for (iter = predefined_crc_table; iter->name; iter++) {
		if (!strcmp(iter->name, name)) {
			found = iter;
			break;
		}
	}

	return found;
}

void list_predefined_crcs(void)
{
	ft_table_t *table;
	const struct named_crc *iter;

	table = ft_create_table();

	ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
	ft_write_ln(table, "Name", "Polynomial", "Reversed", "Start Value", "Output XOR");

	for (iter = predefined_crc_table; iter->name; iter++) {
		ft_printf_ln(table, "%s|0x%lx|%s|0x%x|0x%x",
			     iter->name,
			     iter->settings.polynomial,
			     iter->settings.rev ? "yes" : "no",
			     iter->settings.start_value,
			     iter->settings.xor);
	}

	printf("%s\n", ft_to_string(table));
	ft_destroy_table(table);
}
