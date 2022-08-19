#include <patchelfcrc/named_crcs.h>
#include <stddef.h>
#include <string.h>

#define NAMED_CRC(crc_name, poly, reverse, init, outxor) { \
	.name = crc_name, \
	.settings = { \
		.polynomial = poly, \
		.xor = outxor, \
		.start_value = init, \
		.rev = reverse \
}}

const struct named_crc predefined_crc_table[] = {
	NAMED_CRC("crc-8", 0x07, false, 0x00, 0x00),
	NAMED_CRC("crc-8-darc", 0x39, true, 0x00, 0x00),
	NAMED_CRC("crc-8-i-code", 0x1D, false, 0xFD, 0x00),
	NAMED_CRC("crc-8-itu", 0x07, false, 0x55, 0x55),
	NAMED_CRC("crc-8-maxim", 0x31, true, 0x00, 0x00),
	NAMED_CRC("crc-8-rohc", 0x07, true, 0xFF, 0x00),
	NAMED_CRC("crc-8-wcdma", 0x9B, true, 0x00, 0x00),
	NAMED_CRC("crc-16", 0x8005, true, 0x0000, 0x0000),
	NAMED_CRC("crc-16-buypass", 0x8005, false, 0x0000, 0x0000),
	NAMED_CRC("crc-16-dds-110", 0x8005, false, 0x800D, 0x0000),
	NAMED_CRC("crc-16-dect", 0x0589, false, 0x0001, 0x0001),
	NAMED_CRC("crc-16-dnp", 0x3D65, true, 0xFFFF, 0xFFFF),
	NAMED_CRC("crc-16-en-13757", 0x3D65, false, 0xFFFF, 0xFFFF),
	NAMED_CRC("crc-16-genibus", 0x1021, false, 0x0000, 0xFFFF),
	NAMED_CRC("crc-16-maxim", 0x8005, true, 0xFFFF, 0xFFFF),
	NAMED_CRC("crc-16-mcrf4xx", 0x1021, true, 0xFFFF, 0x0000),
	NAMED_CRC("crc-16-riello", 0x1021, true, 0x554D, 0x0000),
	NAMED_CRC("crc-16-t10-dif", 0x8BB7, false, 0x0000, 0x0000),
	NAMED_CRC("crc-16-teledisk", 0xA097, false, 0x0000, 0x0000),
	NAMED_CRC("crc-16-usb", 0x8005, true, 0x0000, 0xFFFF),
	NAMED_CRC("x-25", 0x1021, true, 0x0000, 0xFFFF),
	NAMED_CRC("xmodem", 0x1021, false, 0x0000, 0x0000),
	NAMED_CRC("modbus", 0x8005, true, 0xFFFF, 0x0000),
	NAMED_CRC("kermit [1]", 0x1021, true, 0x0000, 0x0000),
	NAMED_CRC("crc-ccitt-false [1]", 0x1021, false, 0xFFFF, 0x0000),
	NAMED_CRC("crc-aug-ccitt [1]", 0x1021, false, 0x1D0F, 0x0000),
	NAMED_CRC("crc-24", 0x864CFB, false, 0xB704CE, 0x000000),
	NAMED_CRC("crc-24-flexray-a", 0x5D6DCB, false, 0xFEDCBA, 0x000000),
	NAMED_CRC("crc-24-flexray-b", 0x5D6DCB, false, 0xABCDEF, 0x000000),
	NAMED_CRC("crc-32", 0x04C11DB7, true, 0x00000000, 0xFFFFFFFF),
	NAMED_CRC("crc-32-bzip2", 0x04C11DB7, false, 0x00000000, 0xFFFFFFFF),
	NAMED_CRC("crc-32c", 0x1EDC6F41, true, 0x00000000, 0xFFFFFFFF),
	NAMED_CRC("crc-32d", 0xA833982B, true, 0x00000000, 0xFFFFFFFF),
	NAMED_CRC("crc-32-mpeg", 0x04C11DB7, false, 0xFFFFFFFF, 0x00000000),
	NAMED_CRC("posix", 0x04C11DB7, false, 0xFFFFFFFF, 0xFFFFFFFF),
	NAMED_CRC("crc-32q", 0x814141AB, false, 0x00000000, 0x00000000),
	NAMED_CRC("jamcrc", 0x04C11DB7, true, 0xFFFFFFFF, 0x00000000),
	NAMED_CRC("xfer", 0x000000AF, false, 0x00000000, 0x00000000),
	/* SENTINEL */
	{.name = NULL, .settings = {0, 0, 0, false}},
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
		if (strcmp(iter->name, name)) {
			found = iter;
			break;
		}
	}

	return found;
}
