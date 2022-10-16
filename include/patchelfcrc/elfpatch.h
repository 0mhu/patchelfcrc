#ifndef _ELFPATCH_H_
#define _ELFPATCH_H_

#include <libelf.h>

struct elfpatch {
    int fd;
    Elf *elf;
};

int elf_patch_open(struct elfpatch *ep, const char *path);

void elf_patch_print_stats(const struct elfpatch *ep);

void elf_patch_close(struct elfpatch *ep);

#endif /* _ELFPATCH_H_ */
