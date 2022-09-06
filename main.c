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

#include <stdio.h>
#include <libelf.h>
#include <argp.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <patchelfcrc/named_crcs.h>
#include <patchelfcrc/crc.h>
#include <patchelfcrc/version.h>
#include <linklist-lib/singly-linked-list.h>

#define print_err(fmt, ...) fprintf(stderr, (fmt), ## __VA_ARGS__);
#define print_debug(fmt, ...) do { \
				if (verbose) { \
					printf("[DBG] "fmt, ## __VA_ARGS__); \
				} \
				} while (0)

const char *argp_program_bug_address = "<mario.huettel@linux.com>";

enum granularity {
	GRANULARITY_BYTE = 8,
	GRANULARITY_16BIT = 16,
	GRANULARITY_32BIT = 32,
};

enum crc_format {
	FORMAT_BARE = 0,
	FORMAT_STRUCT,
};

#define ARG_KEY_DRY_RUN (1)
#define ARG_KEY_START_MAGIC (2)
#define ARG_KEY_END_MAGIC (3)
#define ARG_KEY_LIST (4)

struct command_line_options {
	bool little_endian;
	bool dry_run;
	bool verbose;
	enum granularity granularity;
	enum crc_format format;
	struct crc_settings crc;
	bool has_start_magic;
	uint32_t start_magic;
	bool has_end_magic;
	uint32_t end_magic;
	bool list;
	SlList *section_list;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct command_line_options *args = (struct command_line_options *)state->input;
	const struct named_crc *looked_up_crc;
	char *endptr;

	switch (key) {
	case ARG_KEY_DRY_RUN:
		args->dry_run = true;
		args->verbose = true;
		break;
	case ARG_KEY_START_MAGIC:
		args->has_start_magic = true;
		args->start_magic = strtoul(arg, NULL, 0);
		break;
	case ARG_KEY_END_MAGIC:
		args->has_end_magic = true;
		args->end_magic = strtoul(arg, NULL, 0);
		break;
	case ARG_KEY_LIST:
		args->list = true;
		break;
	case 'p':
		/* Polyniomial */
		args->crc.polynomial = strtoull(arg, &endptr, 0);
		if (endptr == arg) {
			if ((looked_up_crc = lookup_named_crc(arg))) {
				memcpy(&args->crc, &looked_up_crc->settings, sizeof(struct crc_settings));
			} else {
				argp_error(state, "Error parsing polynomial: %s\n", arg);
			}
		}
		break;
	case 'l':
		args->little_endian = true;
		break;
	case 'v':
		args->verbose = true;
		break;
	case 'S':
		/* Section */
		args->section_list = sl_list_append(args->section_list, strdup(arg));
		break;
	case 'g':
		if (!strcmp(arg, "byte"))
			args->granularity = GRANULARITY_BYTE;
		else if  (!strcmp(arg, "halfword"))
			args->granularity = GRANULARITY_16BIT;
		else if  (!strcmp(arg, "word"))
			args->granularity = GRANULARITY_32BIT;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}


	return 0;
}

static int parse_cmdline_options(int *argc, char ***argv, struct command_line_options *cmd_opts)
{
	const int crc_param_group = 1;
	error_t err;

	if (!argc || !argv)
		return -1000;

	static struct argp_option options[] = {
		{"little-endian", 'l', 0, 0, "Memory image is little endian. Only relevant if granularity is greater than a single byte", 0},
		{"granularity", 'g', "GRANULARITY", 0, "Granularity to calculate the CRC for", 0},
		{"poly", 'p', "POLYNOMIAL", 0, "Polynomial to use", crc_param_group},
		{"start-value", 's', "STARTVALUE", 0, "Start value for CRC calculation", crc_param_group},
		{"reversed", 'r', 0, 0, "Bit reversed CRC", crc_param_group},
		{"xor-out", 'x', "XORVAL", 0, "XOR the output with XORVAL. Default 0x0", crc_param_group},
		{"dry-run", ARG_KEY_DRY_RUN, 0, 0, "Dry run. Caclualate CRCs but do not patch output file. Implicitly activates verbose mode.", 0},
		{"verbose", 'v', 0, 0, "Verbose output", 0},
		{"section", 'S', "SEC", 0, "Section to calculate CRC for", 2},
		{"output-section", 'O', "OUTPUTSEC", 0, "Output section for generated CRCs", 2},
		{"crc-format", 'F', "FORMAT", 0, "Output Format for CRCs.", 2},
		{"start-magic", ARG_KEY_START_MAGIC, "STARTMAGIC", 0, "Check output section for start magic (uint32)", 2},
		{"end-magic", ARG_KEY_END_MAGIC, "STARTMAGIC", 0, "Check output section for start magic (uint32)", 2},
		{"list-crcs", ARG_KEY_LIST, 0, 0 , "List predefined CRCs", 0},
		/* Sentinel */
		{NULL, 0, 0, 0, NULL, 0}
	};

	static struct argp arg_parser = {
		options,
		parse_opt,
		NULL,
		NULL,
		0, 0, 0
	};

	err = argp_parse(&arg_parser, *argc, *argv, 0, 0, cmd_opts);

	return err ? -1 : 0;
}

static void prepare_default_opts(struct command_line_options *opts)
{
	opts->little_endian = false;
	opts->verbose = false;
	opts->granularity = GRANULARITY_BYTE;
	opts->dry_run = false;
	opts->crc.xor = 0UL;
	opts->crc.polynomial = 0x104C11DB7UL;
	opts->crc.start_value = 0xFFFFFFFFUL;
	opts->crc.rev = false;
	opts->format = FORMAT_BARE;
	opts->has_end_magic = false;
	opts->has_start_magic = false;
	opts->list = false;
	opts->section_list = NULL;
}

static void print_verbose_start_info(const struct command_line_options *cmd_opts)
{
	bool verbose = cmd_opts->verbose;
	int i;
	SlList *list_iter;
	const struct named_crc *predef_crc;

	print_debug("Start CRC patching\n");
	print_debug("Endianess: %s endian\n", (cmd_opts->little_endian ? "little" : "big"));
	print_debug("Granularity: %u bits\n", (unsigned int)cmd_opts->granularity);
	if (cmd_opts->has_start_magic)
		print_debug("Checking for start magic: 0x%08x\n", (unsigned int)cmd_opts->start_magic);
	if (cmd_opts->has_end_magic)
		print_debug("Checking for end magic: 0x%08x\n", (unsigned int)cmd_opts->end_magic);
	if (cmd_opts->dry_run)
		print_debug("Dry run mode selected. Will not touch ELF file.\n");
	predef_crc = reverse_lookup_named_crc(&cmd_opts->crc);
	if (predef_crc) {
		print_debug("Predefined CRC detected: %s\n", predef_crc->name);
	} else {
		print_debug("Generator polynomial: 0x%lx\n", cmd_opts->crc.polynomial);
		print_debug("Start value: 0x%x\n", cmd_opts->crc.start_value);
		print_debug("Output XOR: 0x%x\n", cmd_opts->crc.xor);
		print_debug("Reversed: %s\n", cmd_opts->crc.rev ? "yes" : "no");
		print_debug("CRC length: %d\n", crc_len_from_poly(cmd_opts->crc.polynomial));
	}

	if (cmd_opts->section_list) {
		for (list_iter = cmd_opts->section_list, i = 1; list_iter; list_iter = sl_list_next(list_iter), i++) {
			print_debug("Input section [%d]: \"%s\"\n", i, (const char *)list_iter->data);
		}
	}

}

static void free_cmd_args(struct command_line_options *opts)
{
	SlList *list_iter;

	/* Free the output section names */
	for (list_iter = opts->section_list; list_iter; list_iter = sl_list_next(list_iter)) {
		if (list_iter->data)
			free(list_iter->data);
	}

	/* Free the section list */
	sl_list_free(opts->section_list);
	opts->section_list = NULL;
}

int main(int argc, char **argv)
{
	bool verbose;
	struct crc_calc crc;
	struct command_line_options cmd_opts;

	prepare_default_opts(&cmd_opts);
	parse_cmdline_options(&argc, &argv, &cmd_opts);

	verbose = cmd_opts.verbose || cmd_opts.dry_run;
	print_verbose_start_info(&cmd_opts);

	if (cmd_opts.list) {
		list_predefined_crcs();
		goto free_cmds;
	}

	/* Build the CRC */
	crc_init(&crc, &cmd_opts.crc);

	/* Perform the check test */
	crc_push_bytes(&crc, "123456789", 9u);
	crc_finish_calc(&crc);
	printf("CRC Check value: 0x%08x\n", crc_get_value(&crc));

	crc_destroy(&crc);
free_cmds:

	free_cmd_args(&cmd_opts);

	return 0;
}
