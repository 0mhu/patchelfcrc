#ifndef _ELFPATCH_H_
#define _ELFPATCH_H_

#include <stdint.h>

typedef struct elfpatch elfpatch_handle_t;

elfpatch_handle_t *elf_patch_open(const char *path);

void elf_patch_close_and_free(elfpatch_handle_t *ep);

#endif /* _ELFPATCH_H_ */
