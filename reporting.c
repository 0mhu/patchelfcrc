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
