#ifndef _REPORTING_H_
#define _REPORTING_H_

#include <stdbool.h>

#define print_err(fmt, ...) fprintf(stderr, "[ERR] " fmt, ## __VA_ARGS__);

void print_debug(const char *fmt, ...);

void reporting_enable_verbose(void);

bool reporting_get_verbosity(void);

#endif /* _REPORTING_H_ */
