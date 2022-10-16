#ifndef _REPORTING_H_
#define _REPORTING_H_

#define print_err(fmt, ...) fprintf(stderr, (fmt), ## __VA_ARGS__);

void print_debug(const char *fmt, ...);

void reporting_enable_verbose(void);

#endif /* _REPORTING_H_ */
