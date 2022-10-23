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
	bool readonly;
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

/**
 * @brief Convert a series of 4 bytes into a uint32_t dpending on endianess
 * @param data 4 bytes
 * @param little_endian data is little endian
 * @return uint32
 */
static uint32_t get_uint32_from_byte_string(const uint8_t *data, bool little_endian)
{
	uint32_t out = 0ul;
	int i;

	for (i = 0; i < 4; i++) {
		if (little_endian)
			out >>= 8u;
		else
			out <<= 8u;

		out |= (((uint32_t)data[i]) << (little_endian ? 24u : 0u));
	}

	return out;
}

static void write_crc_to_byte_array(uint8_t *byte_array, uint32_t crc, uint8_t crc_size_bytes, bool little_endian)
{
	int i;

	if (!byte_array)
		return;

	for (i = 0; i < crc_size_bytes; i++) {
		if (little_endian) {
			byte_array[i] = (uint8_t)(crc & 0xFFul);
			crc >>= 8u;
		} else {
			byte_array[i] = (uint8_t)((crc & 0xFF000000ul) >> 24u);
			crc <<= 8u;
		}
	}
}

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

elfpatch_handle_t *elf_patch_open(const char *path, bool readonly)
{
	struct elfpatch *ep;

	if (!path) {
		print_err("Internal error while opeing ELF file. No path specified\n");
		return NULL;
	}

	ep = (struct elfpatch *)calloc(1u, sizeof(struct elfpatch));
	ep->magic = ELFPATCH_MAGIC;
	ep->readonly = readonly;

	ep->fd = open(path, readonly ? O_RDONLY : O_RDWR, 0);
	if (ep->fd < 0) {
		print_err("Error opening file: %s\n", path);
		goto free_struct;
	}
	ep->elf = elf_begin(ep->fd, readonly ? ELF_C_READ : ELF_C_RDWR, NULL);
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

int elf_patch_write_crcs_to_section(elfpatch_handle_t *ep, const char *section, const SlList *section_name_list,
				    const uint32_t *crcs, uint8_t crc_size_bits, uint32_t start_magic, uint32_t end_magic,
				    bool check_start_magic, bool check_end_magic, enum crc_format format, bool little_endian)
{
	int ret = -1;
	struct elf_section *output_section;
	Elf_Data *output_sec_data;
	const SlList *iter;
	size_t needed_space;
	size_t crc_count;
	uint8_t crc_size_bytes;
	uint8_t *sec_bytes;
	size_t idx;

	ret_val_if_ep_err(ep, -1000);

	print_debug("== Patch output file ==\n");

	if (crc_size_bits < 1u || crc_size_bits > 32u) {
		print_err("Unsupported CRC size: %u", (unsigned int)crc_size_bits);
		return -1;
	}

	if (format != FORMAT_BARE) {
		print_err("Currently only bare format is supported!\n");
		return -1;
	}

	/* All pointer parameters are required */
	if (!section || !section_name_list || !crcs)
		return -1000;

	output_section = find_section_in_list(ep->sections, section);
	if (!output_section) {
		print_err("Cannot find output section '%s' to place CRCs. Exiting.\n", section);
		goto ret_err;
	}

	/* Get data object of section */
	output_sec_data = elf_getdata(output_section->scn, NULL);
	sec_bytes = (uint8_t *)output_sec_data->d_buf;

	/* Check the start and end magics */
	if (check_start_magic) {
		if (get_uint32_from_byte_string(sec_bytes, little_endian) != start_magic) {
			print_err("Start magic does not match: expected: 0x%08x, got: 0x%08x\n",
				  start_magic, get_uint32_from_byte_string(sec_bytes, little_endian));
			goto ret_err;
		}
		print_debug("Start magic matching: 0x%08x\n", start_magic);
	}
	if (check_end_magic) {
		if (get_uint32_from_byte_string(&sec_bytes[output_sec_data->d_size - 4], little_endian) != end_magic) {
			print_err("End magic does not match: expected: 0x%08x, got: 0x%08x\n",
				  end_magic,
				  get_uint32_from_byte_string(&sec_bytes[output_sec_data->d_size - 4], little_endian));
			goto ret_err;
		}
		print_debug("End magic matching: 0x%08x\n", end_magic);
	}

	/* Calculate Bytes needed for CRC */
	crc_size_bytes = (crc_size_bits + 7u) / 8u;
	crc_count = sl_list_length(section_name_list);

	print_debug("CRC requires %u bytes.\n", (unsigned int)crc_size_bytes);
	switch (format) {
	case FORMAT_BARE:
		needed_space = crc_size_bytes * crc_count;
		break;
	default:
		needed_space = 0;
		print_err("Unsupported CRC output format\n");
		goto ret_err;
	}
	/* Add existing magic numbers to required space */
	if (check_start_magic)
		needed_space += 4u;
	if (check_end_magic)
		needed_space += 4u;

	print_debug("Required space for %zu CRCs %s: %zu (available: %zu)\n",
		    crc_count,
		    (check_start_magic || check_end_magic ? "including magic values" : ""),
		    needed_space,
		    output_sec_data->d_size
		    );
	if (needed_space > output_sec_data->d_size) {
		print_err("Not enough space in section. %zu bytes available but %zu needed\n",
			  output_sec_data->d_size, needed_space);
	}

	/* Checks finished. Write data to output section */
	if (format == FORMAT_BARE) {
		if (check_start_magic)
			sec_bytes += 4;

		for (iter = section_name_list, idx = 0; iter; iter = sl_list_next(iter), idx++) {
			print_debug("Write CRC 0x%08x (%u bytes) for section %s\n", crcs[idx],
				    (unsigned int)crc_size_bytes,
				    iter->data);
			write_crc_to_byte_array(sec_bytes, crcs[idx], crc_size_bytes, little_endian);
			sec_bytes += crc_size_bytes;
		}
	}

	/* Update ELF file */
	if (ep->readonly) {
		print_debug("DRY RUN: File will not be updated\n");
		ret = 0;
	} else {
		if (elf_update(ep->elf, ELF_C_WRITE) < 0) {
			print_err("Error writing ELF file: %s\n", elf_errmsg(-1));
		} else {
			ret = 0;
		}
	}

ret_err:
	return ret;
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
