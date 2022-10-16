#include <patchelfcrc/elfpatch.h>
#include <patchelfcrc/reporting.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

#define print_err(fmt, ...) fprintf(stderr, (fmt), ## __VA_ARGS__);

int elf_patch_open(struct elfpatch *ep, const char *path)
{
	int fd;
	Elf *elf;

	if (!ep || !path)
		return -1000;

	memset(ep, 0, sizeof(struct elfpatch));

	fd = open(path, O_RDWR, 0);
	if (fd < 0) {
		print_err("Error opening file: %s\n", path);
		return -1;
	}
	elf = elf_begin(fd, ELF_C_RDWR, NULL);
	if (!elf) {
		close(fd);
		print_err("[LIBELF] %s\n", elf_errmsg(-1));
		return -1;
	}

	ep->fd = fd;
	ep->elf = elf;

	return 0;
}

void elf_patch_print_stats(const struct elfpatch *ep)
{
	Elf_Kind ek;
	const char *type_string = "unrecognized";

	if (!ep || !ep->elf)
		return;

	ek = elf_kind(ep->elf);

	switch (ek) {
	case ELF_K_AR:
		type_string = "archive";
		break;
	case ELF_K_ELF:
		type_string = "elf object";
		break;
	default:
		/* Unrecognized is the default. Do nothing */
		break;
	}
	print_debug("ELF File Type: %s\n", type_string);
}

void elf_patch_close(struct elfpatch *ep)
{
	if (!ep)
		return;
	if (ep->elf)
		elf_end(ep->elf);

	if (ep->fd > 0)
		close(ep->fd);

	ep->elf = NULL;
	ep->fd = 0;
}
