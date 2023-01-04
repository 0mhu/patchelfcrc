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
#include <patchelfcrc/reporting.h>
#include <patchelfcrc/elfpatch.h>
#include <patchelfcrc/xml.h>
#include <fort.h>

const char *argp_program_bug_address = "<mario [dot] huettel [at] linux [dot] com>";

#define ARG_KEY_DRY_RUN (1)
#define ARG_KEY_START_MAGIC (2)
#define ARG_KEY_END_MAGIC (3)
#define ARG_KEY_LIST (4)
#define ARG_KEY_EXPORT (5)
#define ARG_KEY_IMPORT (6)
#define ARG_KEY_XSD (7)

struct command_line_options {
	bool little_endian;
	bool dry_run;
	bool verbose;
	bool print_xsd;
	enum granularity granularity;
	enum crc_format format;
	struct crc_settings crc;
	bool has_start_magic;
	uint32_t start_magic;
	bool has_end_magic;
	uint32_t end_magic;
	bool list;
	SlList *section_list;
	const char *elf_path;
	const char *output_section;
	const char *export_xml;
	const char *import_xml;
};

/**
 * @brief Parse command line options
 * @param key Option key
 * @param arg Argument passed
 * @param state State of ARGP parser
 * @return 0 No error
 * @return ARGP_ERR_UNKNOWN in case of an unknown option
 */
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
	case ARG_KEY_EXPORT:
		args->export_xml = arg;
		break;
	case ARG_KEY_IMPORT:
		args->import_xml = arg;
		break;
	case ARG_KEY_LIST:
		args->list = true;
		break;
	case ARG_KEY_XSD:
		args->print_xsd = true;
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
		else
			argp_error(state, "Error parsing granularity: %s\n", arg);
		break;
	case 'F':
		if (!strcmp(arg, "bare"))
			args->format = FORMAT_BARE;
		else if (!strcmp(arg, "struct"))
			args->format = FORMAT_STRUCT;
		else
			argp_error(state, "Error parsing output format: %s\n", arg);
		break;
	case 'O':
		args->output_section = arg;
		break;
	case 'r':
		args->crc.rev = true;
		break;
	case 's':
		args->crc.start_value = strtoul(arg, NULL, 0);
		break;
	case 'x':
		args->crc.xor = strtoul(arg, NULL, 0);
		break;
	case ARGP_KEY_ARG:
		if (state->arg_num >= 1)
			argp_usage(state);
		else
			args->elf_path = arg;
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
		{"list-crcs", ARG_KEY_LIST, 0, 0, "List predefined CRCs", 0},
		{"export", ARG_KEY_EXPORT, "XML", 0, "Export CRCs to XML file", 3},
		{"import", ARG_KEY_IMPORT, "XML", 0, "Do not caclulate CRCs but import them from file", 3},
		{"xsd", ARG_KEY_XSD, 0, 0, "Print XSD to stdout", 0},
		/* Sentinel */
		{NULL, 0, 0, 0, NULL, 0}
	};

	static struct argp arg_parser = {
		options,
		parse_opt,
		"ELF",
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
	opts->print_xsd = false;
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
	opts->elf_path = NULL;
	opts->output_section = NULL;
	opts->export_xml = NULL;
	opts->import_xml = NULL;
}

static void print_verbose_start_info(const struct command_line_options *cmd_opts)
{
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

	if (cmd_opts->elf_path) {
		print_debug("ELF file: %s\n", cmd_opts->elf_path);
	}

	if (cmd_opts->output_section) {
		print_debug("Output section: %s\n", cmd_opts->output_section);
	}

	if (cmd_opts->export_xml) {
		print_debug("Export CRCs to '%s'\n", cmd_opts->export_xml);
	}

	if (cmd_opts->import_xml) {
		print_debug("Import CRCs from '%s'\n", cmd_opts->import_xml);
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

/**
 * @brief check_all_sections_present
 * @param ep
 * @param list
 * @return -1 if no sections are provided. 0 if all sections are present. -2 if setions cannot be found
 */
static int check_all_sections_present(elfpatch_handle_t *ep, SlList *list)
{
	SlList *iter;
	const char *sec_name;
	int ret = 0;

	if (!ep)
		return -1001;
	if (!list) {
		print_err("No input sections specified.\n")
		return -1;
	}
	for (iter = list; iter; iter = sl_list_next(iter)) {
		sec_name = (const char *)iter->data;
		if (!sec_name)
			continue;
		if (elf_patch_check_for_section(ep, sec_name)) {
			print_err("Cannot find section '%s'\n", sec_name);
			ret = -2;
		} else {
			print_debug("Input section '%s': found\n", sec_name);
		}
	}

	return ret;
}

/**
 * @brief Compute CRCs over the sections in @p list
 * @param ep Elf patch
 * @param list List of section names to patch
 * @param opts Command line options. Used for CRC generation
 * @param[out] crcs Array of output CRCs. Must be large enough to hold all elements
 * @return 0 if successful
 */
static int compute_crcs(elfpatch_handle_t *ep, SlList *list, const struct command_line_options *opts, uint32_t *crcs)
{
	SlList *iter;
	const char *sec_name;
	int ret = 0;
	struct crc_calc _crc;
	struct crc_calc * const crc = &_crc;
	unsigned int idx;

	/* Construct the CRC */
	crc_init(crc, &opts->crc);

	for (iter = list, idx = 0; iter; iter = sl_list_next(iter), idx++) {
		crc_reset(crc);
		sec_name = (const char *)iter->data;
		if (elf_patch_compute_crc_over_section(ep, sec_name, crc, opts->granularity, opts->little_endian)) {
			print_err("Error during CRC calculation. Exiting.\n");
			ret = -1;
			break;
		}
		crc_finish_calc(crc);
		crcs[idx] = crc_get_value(crc);
	}

	crc_destroy(crc);
	return ret;
}

/**
 * @brief Debug-print the CRCs of sections in form of a table
 * @param[in] list List of section names
 * @param[in] crcs Array of CRCs.
 * @note The array @p crcs must be at least as long as @p list
 */
static void print_crcs(SlList *list, const uint32_t *crcs)
{
	SlList *iter;
	unsigned int idx;
	const char *sec_name;
	ft_table_t *table;

	table = ft_create_table();

	/* Write header */
	ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
	ft_write_ln(table, "Section", "CRC");

	for (iter = list, idx = 0; iter; iter = sl_list_next(iter), idx++) {
		sec_name = (const char *)iter->data;
		ft_printf_ln(table, "%s|0x%x", sec_name, crcs[idx]);
	}
	print_debug("Calculated CRCs:\n%s\n", ft_to_string(table));
	ft_destroy_table(table);
}

int main(int argc, char **argv)
{
	struct command_line_options cmd_opts;
	elfpatch_handle_t *ep;
	int ret = 0;
	uint32_t *crcs;

	xml_init();

	prepare_default_opts(&cmd_opts);
	parse_cmdline_options(&argc, &argv, &cmd_opts);
	if (cmd_opts.print_xsd) {
		xml_print_xsd();
		goto free_cmds;
	}

	if (cmd_opts.verbose || cmd_opts.dry_run)
		reporting_enable_verbose();
	print_verbose_start_info(&cmd_opts);

	if (cmd_opts.list) {
		list_predefined_crcs();
		goto free_cmds;
	}

	/* Check if file has been supplied */
	if (!cmd_opts.elf_path) {
		print_err("No ELF file specified. Exiting...\n");
		return -1;
	}

	if (cmd_opts.export_xml && cmd_opts.import_xml) {
		print_err("XML export and input cannot be specified at the same time.");
		return -2;
	}

	if (!cmd_opts.output_section && cmd_opts.export_xml == NULL) {
		print_err("No output section / XML export specified. Will continue but not create any output\n");
	}

	/* Do error printing if using a reversed polynomial. It is not implemented yet! */
	if (cmd_opts.crc.rev) {
		print_err("Reversed polynomials are not supported yet\nExiting...\n");
		goto free_cmds;
	}

	/* Prepare libelf for use with the latest ELF version */
	elf_version(EV_CURRENT);

	/* Open the ELF file */
	ep = elf_patch_open(cmd_opts.elf_path, cmd_opts.dry_run, cmd_opts.little_endian);
	if (!ep) {
		ret = -2;
		goto free_cmds;
	}

	/* Check if all sections are present */
	if (check_all_sections_present(ep, cmd_opts.section_list)) {
		ret = -2;
		goto ret_close_elf;
	}

	/* Compute CRCs over sections */
	crcs = (uint32_t *)malloc(sl_list_length(cmd_opts.section_list) * sizeof(uint32_t));
	if (compute_crcs(ep, cmd_opts.section_list, &cmd_opts, crcs)) {
		goto ret_close_elf;
	}

	if (reporting_get_verbosity()) {
		print_crcs(cmd_opts.section_list, crcs);
	}

	if (cmd_opts.output_section) {
		if (elf_patch_write_crcs_to_section(ep, cmd_opts.output_section, cmd_opts.section_list,
					crcs, crc_len_from_poly(cmd_opts.crc.polynomial),
					cmd_opts.start_magic, cmd_opts.end_magic,
					cmd_opts.has_start_magic, cmd_opts.has_end_magic,
					cmd_opts.format, cmd_opts.little_endian)) {
			ret = -1;
		}
	}

	if (cmd_opts.export_xml) {
		if (xml_write_crcs_to_file(cmd_opts.export_xml, crcs, cmd_opts.section_list, &cmd_opts.crc, ep)) {
			print_err("Error during XML generation\n");
			ret = -3;
		}
		/* Fix this: */
		(void)xml_import_from_file(cmd_opts.export_xml);

	}

ret_close_elf:
	elf_patch_close_and_free(ep);

	/* Free the CRCs. This is not strictly necessary... */
	free(crcs);
free_cmds:
	free_cmd_args(&cmd_opts);

	return ret;
}
