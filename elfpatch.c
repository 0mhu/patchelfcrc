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
#include <fort.h>

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
		if (sec->name)
			free(sec->name);
		sec->name = NULL;
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

static void print_sections(elfpatch_handle_t *ep)
{
	SlList *iter;
	ft_table_t *table;
	const struct elf_section *section;

	ret_if_ep_err(ep);

	if (!ep->sections) {
		print_err("No sections found\n");
		return;
	}

	if (!reporting_get_verbosity())
		return;

	table = ft_create_table();

	/* Write header */
	ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
	ft_write_ln(table, "Section", "Type", "Size", "Address", "File Offset");

	for (iter = ep->sections; iter; iter = sl_list_next(iter)) {
		section = (const struct elf_section *)iter->data;
		if (!section)
			continue;
		ft_printf_ln(table, "%s|%s|%lu|0x%p|0x%p",
			     section->name,
			     section_type_to_str(section->section_header.sh_type),
			     section->section_header.sh_size,
			     (void *)section->section_header.sh_addr,
			     (void *)section->section_header.sh_offset
			     );
	}

	print_debug("%s\n", ft_to_string(table));

	ft_destroy_table(table);
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

		if (gelf_getshdr(scn, &sec->section_header) != &sec->section_header) {
			print_err("Error reading section header: %s\n", elf_errmsg(-1));
			free(sec);
			continue;
		}
		name = elf_strptr(ep->elf, shstrndx, sec->section_header.sh_name);
		if (name) {
			sec->name = strdup(name);
		}
		ret = sl_list_append(ret, sec);
	}

	ep->sections = ret;

	print_sections(ep);

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

static struct elf_section *find_section_in_list(SlList *list, const char *name)
{
	SlList *iter;
	struct elf_section *ret = NULL;
	struct elf_section *sec;

	for (iter = list; iter; iter = sl_list_next(iter)) {
		sec = (struct elf_section *)iter->data;
		if (strcmp(sec->name, name) == 0) {
			ret = sec;
			break;
		}
	}


	return ret;
}

int elf_patch_check_for_section(elfpatch_handle_t *ep, const char *section)
{
	int ret;

	ret_val_if_ep_err(ep, -1001);

	ret = find_section_in_list(ep->sections, section) ? 0 : -1;

	return ret;
}

static size_t translate_index(size_t index, enum granularity granularity, bool little_endian)
{
	size_t word_idx;
	size_t part_idx;
	size_t d_index;
	size_t gran_in_bytes;

	if (!little_endian || granularity == GRANULARITY_BYTE)
		return index;

	gran_in_bytes = (size_t)granularity / 8u;
	word_idx = index / gran_in_bytes;
	part_idx = index - word_idx * gran_in_bytes;

	d_index = word_idx * gran_in_bytes + gran_in_bytes - 1u - part_idx;

	return d_index;
}

int elf_patch_compute_crc_over_section(elfpatch_handle_t *ep, const char *section, struct crc_calc *crc,
				       enum granularity granularity, bool little_endian)
{
	const struct elf_section *sec;
	Elf_Data *data;
	size_t idx;
	unsigned int gran_in_bytes = (unsigned int)granularity / 8u;
	unsigned int padding_count = 0u;

	ret_val_if_ep_err(ep, -1001);
	if (!section || !crc)
		return -1000;

	/* Find section */
	sec = find_section_in_list(ep->sections, section);
	if (!sec) {
		print_err("Cannot find section %s\n", section);
		return -1;
	}

	data = elf_getdata(sec->scn, NULL);
	if (!data) {
		print_err("Error reading section data from %s: %s\n", section, elf_errmsg(-1));
		return -1;
	}

	print_debug("Section data length: %lu\n", data->d_size);
	if (!data->d_size)
		print_err("Section %s contains no data.\n", section);

	/* If big endian or granularity is byte, simply compute CRC. No reordering is necessary */
	if (!little_endian || granularity == GRANULARITY_BYTE) {
		crc_push_bytes(crc, data->d_buf, data->d_size);
	} else {
		/* Little endian case with > byte sized chunks */

		/* Check granularity vs size of section */
		padding_count = (gran_in_bytes - data->d_size % gran_in_bytes) % gran_in_bytes;
		if (padding_count) {
			print_err("Section '%s' is not a multiple size of the given granularity. %u zero padding bytes will be added.\n",
				  section, padding_count);
		}

		for (idx = 0; idx < data->d_size; idx++) {
			crc_push_byte(crc, ((char *)data->d_buf)[translate_index(idx, granularity, little_endian)]);
		}

		/* Pad with zeroes */
		for (idx = 0; idx < padding_count; idx++) {
			crc_push_byte(crc, 0x00);
		}
	}

	return 0;
}

void elf_patch_close_and_free(elfpatch_handle_t *ep)
{
	ret_if_ep_err(ep);

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
