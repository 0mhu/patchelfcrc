#include <stdio.h>
#include <libelf.h>
#include <argp.h>
#include <stdbool.h>
#include <patchelfcrc/version.h>

#define print_err(fmt, ...) fprintf(stderr, (fmt), ## __VA_ARGS__);
#define print_debug(fmt, ...) do { \
				if (verbose) { \
					printf("[DBG] "fmt, ## __VA_ARGS__); \
				} \
				} while (0)

const char *argp_program_bug_address = "<mario.huettel@linux.com>";

enum granularity {
	GRANULARITY_BYTE = 1,
	GRANULARITY_16BIT,
	GRANULARITY_32BIT,
};

struct command_line_options {
	bool little_endian;
	enum granularity granularity;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct command_line_options *args = (struct command_line_options *)state->input;
	switch (key) {
	case 'l':
		args->little_endian = true;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}


	return 0;
}

static int parse_cmdline_options(int *argc, char ***argv, struct command_line_options *cmd_opts)
{
	error_t err;

	if (!argc || !argv)
		return -1000;

	static struct argp_option options[] = {
		{"little-endian", 'l', 0, 0, "Memory image is little endian. Only relevant if granularity is greater than a single byte", 0},
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

int main(int argc, char **argv)
{
	bool verbose = true;
	struct command_line_options cmd_opts;

	cmd_opts.little_endian = false;
	cmd_opts.granularity = GRANULARITY_BYTE;

	parse_cmdline_options(&argc, &argv, &cmd_opts);

	print_debug("Start CRC patching\n");
	print_debug("Endianess: %s endian\n", (cmd_opts.little_endian ? "little" : "big"));

	return 0;
}
