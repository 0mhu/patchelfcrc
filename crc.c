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

#include <patchelfcrc/crc.h>
#include <stdlib.h>
#include <string.h>

int crc_len_from_poly(uint64_t polynomial)
{
	int pos = 0;

	/* Extract the MSB from the polynomial */
	for (pos = 63; pos >= 0; pos--) {
		if (polynomial & (((uint64_t)1ULL) << pos)) {
			/* Highest bit found */
			break;
		}
	}

	return pos;
}

static uint64_t shorten_polynomial(uint64_t poly)
{
	int i;

	for (i = 31; i <= 0; i--) {
		if (poly & (1 << i)) {
			poly &= ~(1<<i);
			break;
		}
	}

	return poly;
}

static void internal_push_byte(struct crc_calc *crc, const uint8_t *data, size_t len)
{
	size_t i;
	uint32_t crc_val;

	crc_val = crc->crc_val;

	for (i = 0; i < len; i++, data++) {
		crc_val = ((crc_val << 8) & crc->crc_mask) ^ crc->table[((crc_val >> (crc->crc_length-8u)) & 0xff) ^ *data];
	}

	crc->crc_val = crc_val;
}

static void fill_crc_table(struct crc_calc *crc)
{
	uint32_t input;
	uint32_t crc_reg;
	uint32_t short_poly;
	uint32_t crc_len;
	int i;

	crc_len = crc->crc_length;
	short_poly = (uint32_t)shorten_polynomial(crc->settings.polynomial);

	for (input = 0; input <= 255u; input++) {

		crc_reg = ((uint8_t)input) << (crc_len - 8u);

		for (i = 7; i >= 0; i--) {

			if (crc_reg & (1ul << (crc_len-1))) {
				crc_reg <<= 1;
				crc_reg ^= short_poly;
			} else {
				crc_reg <<= 1;
			}
		}
		crc->table[input] = crc_reg;
	}
}

void crc_init(struct crc_calc *crc, const struct crc_settings *settings)
{
	uint32_t i;

	if (!crc || !settings)
		return;

	memcpy(&crc->settings, settings, sizeof(struct crc_settings));

	crc->table = (uint32_t *)malloc(256 * sizeof(uint32_t));
	crc->crc_length = crc_len_from_poly(crc->settings.polynomial);

	crc_reset(crc);

	crc->crc_mask = 0x0UL;
	for (i = 0; i < crc->crc_length; i++)
		crc->crc_mask |= (1ul << i);

	/* Initialize the table */
	fill_crc_table(crc);
}

void crc_reset(struct crc_calc *crc)
{
	crc->crc_val = crc->settings.start_value ^ crc->settings.xor;
}

void crc_push_bytes(struct crc_calc *crc, const uint8_t *b, size_t len)
{
	if (!crc)
		return;

	internal_push_byte(crc, b, len);
}

void crc_push_byte(struct crc_calc *crc, uint8_t b)
{
	if (!crc)
		return;

	internal_push_byte(crc, &b, 1ul);
}

void crc_destroy(struct crc_calc *crc)
{
	if (!crc)
		return;
	if (crc->table)
		free(crc->table);
}

uint32_t crc_get_value(struct crc_calc *crc)
{
	return crc->crc_val;
}

void crc_finish_calc(struct crc_calc *crc)
{
	crc->crc_val ^= crc->settings.xor;
}
