#include <stdio.h>
#include <libelf.h>
#include <argp.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <patchelfcrc/named_crcs.h>
#include <patchelfcrc/version.h>

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
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct command_line_options *args = (struct command_line_options *)state->input;
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
	case 'l':
		args->little_endian = true;
		break;
	case 'v':
		args->verbose = true;
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
	opts->crc.polynomial = 0x04C11DB7UL;
	opts->crc.start_value = 0xFFFFFFFFUL;
	opts->crc.rev = false;
	opts->format = FORMAT_BARE;
	opts->has_end_magic = false;
	opts->has_start_magic = false;
}

static void print_verbose_start_info(const struct command_line_options *cmd_opts)
{
	bool verbose = cmd_opts->verbose;
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
	}

}

int main(int argc, char **argv)
{
	bool verbose;
	struct command_line_options cmd_opts;

	prepare_default_opts(&cmd_opts);
	parse_cmdline_options(&argc, &argv, &cmd_opts);

	verbose = cmd_opts.verbose || cmd_opts.dry_run;
	print_verbose_start_info(&cmd_opts);

	return 0;
}
