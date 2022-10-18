#include <patchelfcrc/elfpatch.h>
#include <patchelfcrc/reporting.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <libelf.h>
#include <gelf.h>
#include <linklist-lib/singly-linked-list.h>

struct elf_section {
	GElf_Shdr section_header;
	Elf_Scn *scn;
	char *name;
};

struct elfpatch {
	uint32_t magic;
	int fd;
	Elf *elf;
	GElf_Ehdr ehdr;
	int class;
	SlList *sections;
};

#define ELFPATCH_MAGIC 0x8545637Aul

#define is_elfpatch_struct(x) ((x) && (x)->magic == (ELFPATCH_MAGIC))

#define ret_if_ep_err(ep) do { \
	if (!is_elfpatch_struct((ep))) { \
	return; \
	} \
	} while(0)

#define ret_val_if_ep_err(ep, val) do { \
	if (!is_elfpatch_struct((ep))) { \
	return (val); \
	} \
	} while(0)

#define print_err(fmt, ...) fprintf(stderr, (fmt), ## __VA_ARGS__);

static void free_elf_section_element(struct elf_section *sec)
{
	if (sec) {
		free(sec->name);
		free(sec);
	}
}

static const char *section_type_to_str(Elf64_Word type)
{
	switch (type) {
	case SHT_NULL:
		return "NULL";
	case SHT_PROGBITS:
		return "PROGBITS";
	case SHT_SYMTAB:
		return "SYMTAB";
	case SHT_STRTAB:
		return "STRTAB";
	case SHT_NOBITS:
		return "NOBITS";
	case SHT_ARM_EXIDX:
		return "ARM_EXIDX";
	case SHT_INIT_ARRAY:
		return "INIT_ARRAY";
	case SHT_FINI_ARRAY:
		return "FINI_ARRAY";
	default:
		break;
	}
	return "unknown";
}

static SlList *elf_patch_get_sections(elfpatch_handle_t *ep)
{
	SlList *ret = NULL;
	Elf_Scn *scn;
	struct elf_section *sec;
	char *name;
	size_t shstrndx;

	ret_val_if_ep_err(ep, NULL);

	if (ep->sections)
		sl_list_free_full(ret, (void (*)(void *))free_elf_section_element);
	ep->sections = NULL;

	if (elf_getshdrstrndx (ep->elf , &shstrndx) != 0) {
		print_err("ELF error: %s\n", elf_errmsg(-1));
		goto ret_free_section_list;
	}

	scn = NULL;
	while ((scn = elf_nextscn(ep->elf, scn)) != NULL) {
		sec = (struct elf_section *)calloc(1u, sizeof(struct elf_section));
		sec->name = NULL;
		sec->scn = scn;
		ret = sl_list_append(ret, sec);
		if (gelf_getshdr(scn, &sec->section_header) != &sec->section_header) {
			print_err("Error reading section header: %s\n", elf_errmsg(-1));
			goto ret_free_section_list;
		}
		name = elf_strptr(ep->elf, shstrndx, sec->section_header.sh_name);
		if (name) {
			print_debug("[SEC] [%s] %s | %zu bytes at 0x%x (File offset: 0x%x) \n",
				    section_type_to_str(sec->section_header.sh_type),
				    name, (size_t)sec->section_header.sh_size,
				    sec->section_header.sh_addr,
				    sec->section_header.sh_offset);
			sec->name = strdup(name);
		}
	}

	ep->sections = ret;

	return ret;

ret_free_section_list:
	sl_list_free_full(ret, (void (*)(void *))free_elf_section_element);
	ret = NULL;
	return ret;
}

static int elf_patch_update_info(elfpatch_handle_t *ep)
{
	Elf_Kind ek;
	const char *type_string = "unrecognized";

	ret_val_if_ep_err(ep, -1001);

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

	if (ek != ELF_K_ELF)
		return -1;

	gelf_getehdr(ep->elf, &ep->ehdr);
	ep->class = gelf_getclass(ep->elf);

	switch (ep->class) {
	case ELFCLASS32:
		print_debug("ELF class: 32 bit\n");
		break;
	case ELFCLASS64:
		print_debug("ELF class: 64 bit\n");
		break;
	default:
		print_err("Unsupported ELF class: %d\n", ep->class);
		return -1;
	}

	if (!elf_patch_get_sections(ep)) {
		print_err("No sections in file.\n");
		return -1;
	}



	return 0;
}

elfpatch_handle_t *elf_patch_open(const char *path)
{
	struct elfpatch *ep;

	if (!path) {
		print_err("Internal error while opeing ELF file. No path specified\n");
		return NULL;
	}

	ep = (struct elfpatch *)calloc(1u, sizeof(struct elfpatch));
	ep->magic = ELFPATCH_MAGIC;

	ep->fd = open(path, O_RDWR, 0);
	if (ep->fd < 0) {
		print_err("Error opening file: %s\n", path);
		goto free_struct;
	}
	ep->elf = elf_begin(ep->fd, ELF_C_RDWR, NULL);
	if (!ep->elf) {
		print_err("[LIBELF] %s\n", elf_errmsg(-1));
		goto close_fd;
	}

	if (elf_patch_update_info(ep)) {
		print_err("File malformatted. Cannot use for CRC patching\n");
		goto close_elf;
	}

	return (elfpatch_handle_t *)ep;
close_elf:
	if (ep->elf) {
		elf_end(ep->elf);
		ep->elf = NULL;
	}
close_fd:
	if (ep->fd > 0) {
		close(ep->fd);
	}
free_struct:
	free(ep);
	ep = NULL;
	return (elfpatch_handle_t *)ep;
}

void elf_patch_close_and_free(elfpatch_handle_t *ep)
{
	ret_if_ep_err(ep);

	if (!ep)
		return;
	if (ep->elf)
		elf_end(ep->elf);

	if (ep->fd > 0)
		close(ep->fd);

	if (ep->sections)
		sl_list_free_full(ep->sections, (void (*)(void *))free_elf_section_element);
	ep->sections = NULL;

	ep->elf = NULL;
	ep->fd = 0;

	free(ep);
}
