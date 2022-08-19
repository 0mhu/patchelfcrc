#ifndef _NAMED_CRCS_H_
#define _NAMED_CRCS_H_

#include <stdint.h>
#include <stdbool.h>

struct crc_settings {
    uint32_t polynomial;
    uint32_t xor;
    uint32_t start_value;
    bool rev;
};

struct named_crc {
    const char *name;
    struct crc_settings settings;
};

const struct named_crc *reverse_lookup_named_crc(const struct crc_settings *settings);

const struct named_crc *lookup_named_crc(const char *name);

void list_predefined_crcs(void);

#endif /* _NAMED_CRCS_H_ */
