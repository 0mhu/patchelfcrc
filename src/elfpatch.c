/*
 * This file is part of patchelfcrc.
 * Copyright (c) 2022 Mario Hüttel.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 only.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */


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
#include <inttypes.h>
#include <patchelfcrc/crc-output-struct.h>
#include <byteswap.h>

static const union  {
	uint8_t data[4];
	uint32_t val;
} _endianess_check_union = {{1u, 2u, 3u, 4u}};

enum endianess {
	END_LITTLE = 0x04030201ul,
	END_BIG = 0x01020304ul,
};

#define HOST_ENDIANESS (_endianess_check_union.val)

struct elf_section {
	GElf_Shdr section_header;
	Elf_Scn *scn;
	char *name;
	uint64_t lma; /**< @Resolved load memory address of a section. May be equivalent to VMA */
};

struct elfpatch {
	uint32_t magic;
	int fd;
	bool readonly;
	Elf *elf;
	GElf_Ehdr ehdr;
	int class;
	SlList *sections;
	GElf_Phdr *program_headers; /**< @brief Program headers */
	size_t program_headers_count; /**< @brief Number of program headers in the program headers array */
};

#define ELFPATCH_MAGIC 0x8545637Aul

#define is_elfpatch_struct(x) ((x) && (x)->magic == (ELFPATCH_MAGIC))

#define ret_if_ep_err(ep) do { \
		if (!is_elfpatch_struct((ep))) { \
			return; \
		} \
	} while (0)

#define ret_val_if_ep_err(ep, val) do { \
		if (!is_elfpatch_struct((ep))) { \
			return val; \
		} \
	} while (0)

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

	/* Always shift in in big endian format */
	for (i = 0; i < 4; i++) {
			out <<= 8u;
		out |= (uint32_t)data[i];
	}

	/* Swap bytes if little endian */
	if (little_endian)
		out = bswap_32(out);

	return out;
}

static void write_crc_to_byte_array(uint8_t *byte_array, uint32_t crc, uint8_t crc_size_bytes, bool little_endian)
{
	int i;

	if (!byte_array)
		return;

	if (!little_endian)
		crc = bswap_32(crc);

	for (i = 0; i < crc_size_bytes; i++) {
		byte_array[i] = (uint8_t)(crc & 0xFFul);
		crc >>= 8u;
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
	case SHT_PREINIT_ARRAY:
		return "PREINIT_ARRAY";
	case SHT_DYNAMIC:
		return "DYNAMIC";
	case SHT_ARM_ATTRIBUTES:
		return "ARM_ATTRIBUTES";
	case SHT_ARM_PREEMPTMAP:
		return "ARM_PREEMPTMAP";
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
	bool alloc, write, exec;

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
	ft_write_ln(table, "Section", "Type", "ALLOC", "WRITE", "EXEC", "Size", "VMA", "LMA", "File Offset");

	for (iter = ep->sections; iter; iter = sl_list_next(iter)) {
		section = (const struct elf_section *)iter->data;
		if (!section)
			continue;

		alloc = !!(section->section_header.sh_flags & SHF_ALLOC);
		write = !!(section->section_header.sh_flags & SHF_WRITE);
		exec = !!(section->section_header.sh_flags & SHF_EXECINSTR);

		ft_printf_ln(table, "%s|%s|%s|%s|%s|%lu|%p|%p|%p",
			     section->name,
			     section_type_to_str(section->section_header.sh_type),
			     alloc ? "x" : "",
			     write ? "x" : "",
			     exec ? "x" : "",
			     section->section_header.sh_size,
			     (void *)section->section_header.sh_addr,
			     (void *)section->lma,
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

	if (elf_getshdrstrndx(ep->elf, &shstrndx) != 0) {
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

		/* Default setting of LMA if not modified by segment */
		sec->lma = (uint64_t)sec->section_header.sh_addr;

		name = elf_strptr(ep->elf, shstrndx, sec->section_header.sh_name);

		if (name)
			sec->name = strdup(name);

		ret = sl_list_append(ret, sec);
	}

	ep->sections = ret;

	return ret;

ret_free_section_list:
	sl_list_free_full(ret, (void (*)(void *))free_elf_section_element);
	ret = NULL;
	return ret;
}

/**
 * @brief Read program headers from ELF file and store them more conviniently in a linkled list
 * @param ep Elfpatch object
 * @return 0 if successful
 * @return negative if error.
 * @note The function will succeed even if no program heder is found in the file.
 */
static int elf_patch_read_program_headers(elfpatch_handle_t *ep)
{
	size_t header_count = 0ull;
	GElf_Phdr *hdr;
	size_t i;

	ret_val_if_ep_err(ep, -1001);

	if (ep->program_headers_count > 0 && ep->program_headers) {
		/* Free the program headers. They are owned by the ELF object. So no need to free them */
		free(ep->program_headers);
		ep->program_headers_count = 0;
	}

	if (elf_getphdrnum(ep->elf, &header_count)) {
		print_err("Error reading program headers: %s\n", elf_errmsg(-1));
		return -1;
	}

	if (header_count == 0) {
		/* No program headers found. This ELF file is probably not linked */
		ep->program_headers_count = 0;
		return 0;
	}

	ep->program_headers = (GElf_Phdr *)malloc(header_count * sizeof(GElf_Phdr));
	if (!ep->program_headers) {
		/* Mem error. Abort. Program will crash eventually */
		return -1;
	}

	for (i = 0u; i < header_count; i++) {
		hdr = &ep->program_headers[i];
		if (gelf_getphdr(ep->elf, (int)i, hdr) != hdr) {
			print_err("Error reading program header (%zu): %s\n", i, elf_errmsg(-1));
			goto ret_free_err;
		}
		print_debug("Program Header (%zu): mem_size: %zu, file_size: %zu, vma: %p, lma: %p, file offset: %zu\n",
			    i,
			    (size_t)hdr->p_memsz, (size_t)hdr->p_filesz, (void *)hdr->p_vaddr, (void *)hdr->p_paddr,
			    hdr->p_offset);
	}

	ep->program_headers_count = header_count;

	return 0;

ret_free_err:
	if (ep->program_headers)
		free(ep->program_headers);
	ep->program_headers_count = 0u;
	return -1;
}

static void resolve_section_lmas(elfpatch_handle_t *ep)
{
	SlList *sec_iter;
	struct elf_section *sec;
	size_t idx;
	uint64_t sec_file_offset;
	uint64_t section_offset_in_segment;
	const GElf_Phdr *phdr;

	ret_if_ep_err(ep);

	for (sec_iter = ep->sections; sec_iter; sec_iter = sl_list_next(sec_iter)) {
		sec = (struct elf_section *)sec_iter->data;
		if (!sec)
			continue;

		/* By default each sections LMA is assumed to be its LMA as well */
		sec->lma = (uint64_t)sec->section_header.sh_addr;

		if (sec->section_header.sh_type == SHT_NOBITS) {
			/* Section does not contain data. It may be allocated but is not loaded. Therefore, LMA=VMA. */
			continue;
		}

		sec_file_offset = (uint64_t) sec->section_header.sh_offset;

		/* Check in which segment the file offset is located */
		for (idx = 0; idx < ep->program_headers_count; idx++) {
			phdr = &ep->program_headers[idx];
			if (sec_file_offset >= phdr->p_offset && sec_file_offset < (phdr->p_offset + phdr->p_filesz)) {
				/* Section lies within this segment */
				section_offset_in_segment = sec_file_offset - phdr->p_offset;
				sec->lma = ((uint64_t)phdr->p_paddr) + section_offset_in_segment;
				break;
			}
		}
	}
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

	if (elf_patch_read_program_headers(ep)) {
		print_err("Error reading program headers.\n");
		return -1;
	}

	/* Resolve section to segment mapping to calculate the LMA of eachs section */
	resolve_section_lmas(ep);

	/* Print the debug section table */
	print_sections(ep);

	return 0;
}

elfpatch_handle_t *elf_patch_open(const char *path, bool readonly, bool expect_little_endian)
{
	struct elfpatch *ep;
	const char *ident;

	/* This is important to guarantee structure packing behavior */
	CRC_OUT_CHECK_STRUCT_SIZES;

	if (!path) {
		print_err("Internal error while opeing ELF file. No path specified\n");
		return NULL;
	}

	ep = (struct elfpatch *)calloc(1u, sizeof(struct elfpatch));
	ep->magic = ELFPATCH_MAGIC;
	ep->readonly = readonly;

	/* This shouldn't really be necessary due to the use of calloc() */
	ep->sections = NULL;
	ep->program_headers = NULL;
	ep->program_headers_count = 0u;

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

	/* Prevent Libelf from relayouting the sections, which would brick the load segments */
	elf_flagelf(ep->elf, ELF_C_SET, ELF_F_LAYOUT);

	if (elf_patch_update_info(ep)) {
		print_err("File malformatted. Cannot use for CRC patching\n");
		goto close_elf;
	}

	ident = elf_getident(ep->elf, NULL);
	if (ident) {
		switch (ident[5]) {
		case 1:
			print_debug("ELF Endianess: little\n");
			if (!expect_little_endian)
				print_err("Big endian format expected. File is little endian. Double check settings!\n");
			break;
		case 2:
			print_debug("ELF Endianess: big\n");
			if (expect_little_endian)
				print_err("Little endian format expected. File is big endian. Double check settings!\n");
			break;
		default:
			print_err("Cannot determine endianess of ELF file. EI_DATA is: %d\n", ident[5]);
			break;
		}
	}

	return (elfpatch_handle_t *)ep;
close_elf:
	if (ep->elf) {
		elf_end(ep->elf);
		ep->elf = NULL;
	}
close_fd:
	if (ep->fd > 0)
		close(ep->fd);
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

static size_t translate_index(size_t index, enum granularity granularity, bool little_endian, bool reversed)
{
	size_t word_idx;
	size_t part_idx;
	size_t d_index;
	size_t gran_in_bytes;

	if ((!little_endian && !reversed) || (little_endian && reversed) || granularity == GRANULARITY_BYTE)
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
	if (!data->d_size) {
		print_err("Section %s contains no data.\n", section);
		return -2;
	}

	/* NOBIT sections have a length but no data in the file. Abort in this case */
	if (!data->d_buf) {
		print_err("Section %s does not contain loadable data.\n", section);
		return -2;
	}

	/* If big endian for non reversed / little endian for reversed or granularity is byte, simply compute CRC. No reordering is necessary */
	if ((!little_endian && !crc->settings.rev) || (little_endian && crc->settings.rev) ||
			granularity == GRANULARITY_BYTE) {
		crc_push_bytes(crc, data->d_buf, data->d_size);
	} else {
		/* Little endian case with > byte sized chunks */

		/* Check granularity vs size of section */
		padding_count = (gran_in_bytes - data->d_size % gran_in_bytes) % gran_in_bytes;
		if (padding_count) {
			print_err("Section '%s' is not a multiple size of the given granularity. %u zero padding bytes will be added.\n",
				  section, padding_count);
		}

		for (idx = 0; idx < data->d_size; idx++)
			crc_push_byte(crc,
				      ((char *)data->d_buf)[
					translate_index(idx, granularity,
						little_endian,
						crc->settings.rev)
					]);

		/* Pad with zeroes */
		for (idx = 0; idx < padding_count; idx++)
			crc_push_byte(crc, 0x00);
	}

	return 0;
}

static size_t calculate_needed_space_for_crcs(enum crc_format format,
					      uint8_t source_elf_bits,
					      bool check_start_magic, bool check_end_magic,
					      uint8_t crc_size_bytes, size_t crc_count)
{
	size_t needed_space = 0ull;

	switch (format) {
	case FORMAT_BARE:
		needed_space = crc_size_bytes * crc_count;
		break;
	case FORMAT_STRUCT:
		/* Calculate space for CRCs including sentinel struct at the end */
		needed_space = (crc_count + 1) *
				(source_elf_bits == 32
					? sizeof(struct crc_out_struct_32bit)
					: sizeof(struct crc_out_struct_64bit));
		break;
	default:
		needed_space = 0;
		print_err("Unsupported CRC output format\n");
	}
	/* Add existing magic numbers to required space */
	if (check_start_magic) {
		needed_space += 4u;
		/* Account for padding after 32 bit magic value in case of structure usage on 64 bit systems */
		if (source_elf_bits == 64 && format == FORMAT_STRUCT)
			needed_space += 4u;
	}
	if (check_end_magic)
		needed_space += 4u;

	return needed_space;
}

static void get_section_addr_and_length(const struct elf_section *sec, uint64_t *vma, uint64_t *len)
{
	if (!sec)
		return;

	if (vma)
		*vma = sec->section_header.sh_addr;
	if (len)
		*len = sec->section_header.sh_size;
}

static void get_section_load_addr(const struct elf_section *sec, uint64_t *lma)
{
	if (!sec || !lma)
		return;

	*lma = sec->lma;
}


int elf_patch_write_crcs_to_section(elfpatch_handle_t *ep, const char *output_sec_name,
				    const struct crc_import_data *crc_data, bool use_vma,
				    uint32_t start_magic, uint32_t end_magic,
				    bool check_start_magic, bool check_end_magic,
				    enum crc_format format, bool little_endian)
{
	int ret = -1;
	uint8_t crc_size_bits;
	struct elf_section *output_section;
	Elf_Data *output_sec_data;
	const SlList *iter;
	size_t needed_space;
	size_t crc_count;
	uint8_t crc_size_bytes;
	uint8_t *sec_bytes;
	size_t idx;
	struct crc_entry *crc_entry;
	struct crc_out_struct_32bit crc_32bit;
	struct crc_out_struct_64bit crc_64bit;
	uint64_t in_sec_addr, in_sec_len;
	bool needs_byteswap;

	ret_val_if_ep_err(ep, -1000);

	print_debug("== Patch output file ==\n");

	crc_size_bits = crc_len_from_poly(crc_data->crc_config.polynomial);

	if (crc_size_bits < 1u || crc_size_bits > 32u) {
		print_err("Unsupported CRC size: %u", (unsigned int)crc_size_bits);
		return -1;
	}

	/* All pointer parameters are required */
	if (!output_sec_name || !crc_data)
		return -1000;

	output_section = find_section_in_list(ep->sections, output_sec_name);
	if (!output_section) {
		print_err("Cannot find output section '%s' to place CRCs. Exiting.\n", output_sec_name);
		goto ret_err;
	}

	/* Get data object of section */
	output_sec_data = elf_getdata(output_section->scn, NULL);
	sec_bytes = (uint8_t *)output_sec_data->d_buf;
	if (!sec_bytes) {
		print_err("Output section '%s' does not contain loadable data. It has to be allocated in the ELF file.\n",
			  output_sec_name);
		goto ret_err;
	}

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
	crc_count = sl_list_length(crc_data->crc_entries);
	if (crc_count < 1) {
		/* No CRCs to patch... */
		ret = -1;
		print_err("No CRCs to patch.\n");
		goto ret_err;
	}

	print_debug("Single CRC requires %u bytes.\n", (unsigned int)crc_size_bytes);

	needed_space = calculate_needed_space_for_crcs(format, crc_data->elf_bits, check_start_magic,
		check_end_magic, crc_size_bytes, crc_count);

	print_debug("Required space for %zu CRCs%s: %zu (available: %zu)\n",
		    crc_count,
		    (check_start_magic || check_end_magic ? " including magic values" : ""),
		    needed_space,
		    output_sec_data->d_size
		    );
	if (needed_space > output_sec_data->d_size) {
		print_err("Not enough space in section. %zu bytes available but %zu needed\n",
			  output_sec_data->d_size, needed_space);
		ret = -1;
		goto ret_err;
	}

	/* Checks finished. Write data to output section */

	if (format == FORMAT_BARE) {
		if (check_start_magic)
			sec_bytes += 4u;
		for (iter = crc_data->crc_entries, idx = 0; iter; iter = sl_list_next(iter), idx++) {
			crc_entry = (struct crc_entry *)iter->data;
			print_debug("Write CRC 0x%08x (%u bytes) for section %s\n", crc_entry->crc,
				(unsigned int)crc_size_bytes,
				crc_entry->name);
			write_crc_to_byte_array(sec_bytes, crc_entry->crc, crc_size_bytes, little_endian);
			sec_bytes += crc_size_bytes;
		}
	} else if (format == FORMAT_STRUCT) {
		if (check_start_magic)
			sec_bytes += 4u;
		if (check_start_magic && crc_data->elf_bits == 64)
			sec_bytes += 4u;

		needs_byteswap = false;
		if ((HOST_ENDIANESS != END_LITTLE && little_endian) ||
				(HOST_ENDIANESS == END_LITTLE && !little_endian)) {
			needs_byteswap = true;
		}

		for (iter = crc_data->crc_entries, idx = 0; iter; iter = sl_list_next(iter), idx++) {
			crc_entry = (struct crc_entry *)iter->data;
			in_sec_addr = use_vma ? crc_entry->vma : crc_entry->lma;
			in_sec_len = crc_entry->size;
			print_debug("Write CRC 0x%08x (%u bytes) for section %s.\n", crc_entry->crc,
				    (unsigned int)crc_size_bytes,
				    crc_entry->name);
			print_debug("Corresponding input section at 0x%"PRIx64", length: %"PRIu64"\n",
				    in_sec_addr,
				    in_sec_len);

			if (crc_data->elf_bits == 32) {
				crc_32bit.crc = needs_byteswap ? bswap_32(crc_entry->crc) : crc_entry->crc;
				crc_32bit.length = needs_byteswap ? bswap_32((uint32_t)in_sec_len) : (uint32_t)in_sec_len;
				crc_32bit.start_address = needs_byteswap ? bswap_32((uint32_t)in_sec_addr) : (uint32_t)in_sec_addr;
				memcpy(sec_bytes, &crc_32bit, sizeof(crc_32bit));
				sec_bytes += sizeof(crc_32bit);
			} else {
				/* 64 bit case */
				crc_64bit.crc = needs_byteswap ? bswap_32(crc_entry->crc) : crc_entry->crc;
				crc_64bit._unused_dummy = 0ul;
				crc_64bit.length = needs_byteswap ? bswap_64(in_sec_len) : in_sec_len;
				crc_64bit.start_address = needs_byteswap ? bswap_64(in_sec_addr) : in_sec_addr;
				memcpy(sec_bytes, &crc_64bit, sizeof(crc_64bit));
				sec_bytes += sizeof(crc_64bit);
			}
		}

		/* Append sentinel struct */
		crc_32bit.crc = 0ul;
		crc_32bit.length = 0ul;
		crc_32bit.start_address = 0ul;

		crc_64bit.crc = 0ul;
		crc_64bit.length = 0ull;
		crc_64bit.start_address = 0ull;

		if (crc_data->elf_bits == 32)
			memcpy(sec_bytes, &crc_32bit, sizeof(crc_32bit));
		else
			memcpy(sec_bytes, &crc_64bit, sizeof(crc_64bit));
	}

	/* Flag section data as invalid to trigger rewrite.
	 * This is needed due to the forced memory layout
	 */
	elf_flagdata(output_sec_data, ELF_C_SET, ELF_F_DIRTY);
	ret = 0;

ret_err:
	return ret;
}

void elf_patch_close_and_free(elfpatch_handle_t *ep)
{
	ret_if_ep_err(ep);

	if (ep->elf) {
		/* Update ELF file */
		if (ep->readonly) {
			print_debug("DRY RUN: File will not be updated\n");
		} else {
			if (elf_update(ep->elf, ELF_C_WRITE) < 0)
				print_err("Error writing ELF file: %s\n", elf_errmsg(-1));
		}
	}

	if (ep->elf)
		elf_end(ep->elf);

	if (ep->fd > 0)
		close(ep->fd);

	if (ep->sections)
		sl_list_free_full(ep->sections, (void (*)(void *))free_elf_section_element);
	ep->sections = NULL;

	if (ep->program_headers) {
		free(ep->program_headers);
		ep->program_headers = NULL;
	}
	ep->program_headers_count = 0u;

	ep->elf = NULL;
	ep->fd = 0;

	free(ep);
}

int elf_patch_get_section_address(elfpatch_handle_t *ep, const char *section,
				  uint64_t *vma, uint64_t *lma, uint64_t *len)
{
	const struct elf_section *sec;

	ret_val_if_ep_err(ep, -1001);
	if (!section)
		return -1002;

	sec = find_section_in_list(ep->sections, section);
	if (!sec)
		return -1;

	get_section_addr_and_length(sec, vma, len);
	get_section_load_addr(sec, lma);

	return 0;
}

int elf_patch_get_bits(elfpatch_handle_t *ep)
{
	int bitsize;

	ret_val_if_ep_err(ep, -1001);

	switch (ep->class) {
	case ELFCLASS32:
		bitsize = 32;
		break;
	case ELFCLASS64:
		bitsize = 64;
		break;
	default:
		bitsize = -1;
		break;
	}

	return bitsize;
}
