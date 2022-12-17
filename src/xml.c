#include <libxml/parser.h>
#include <libxml/xmlIO.h>
#include <libxml/xinclude.h>
#include <libxml/tree.h>
#include <libxml/encoding.h>
#include <libxml/xmlwriter.h>

#include <stdint.h>
#include <inttypes.h>
#include <patchelfcrc/reporting.h>
#include <patchelfcrc/xml.h>

void xml_init(void)
{
	LIBXML_TEST_VERSION;
}

int xml_write_crcs_to_file(const char *path, const uint32_t *crcs, SlList *section_name_list,
			   const struct crc_settings *crc_params, elfpatch_handle_t *ep)
{
	int ret = 0;
	xmlTextWriter *writer;
	SlList *name_iter;
	const char *section_name;
	size_t index;
	uint64_t vma, len;

	if (!path || !crcs || !section_name_list || !crc_params || !ep) {
		return -1000;
	}

	writer = xmlNewTextWriterFilename(path, 0);
	if (!writer) {
		print_err("Cannot create XML file %s\n", path)
		ret = -1;
		goto ret_none;
	}

	xmlTextWriterSetIndentString(writer, BAD_CAST "\t");
	xmlTextWriterSetIndent(writer, 1);

	xmlTextWriterStartDocument(writer, NULL, "UTF-8", NULL);

	xmlTextWriterStartElement(writer, BAD_CAST "settings");
	xmlTextWriterWriteFormatElement(writer, BAD_CAST "poly", "0x%" PRIx64, crc_params->polynomial);
	xmlTextWriterWriteFormatElement(writer, BAD_CAST "start", "0x%" PRIx32, crc_params->start_value);
	xmlTextWriterWriteFormatElement(writer, BAD_CAST "rev", "%s", crc_params->rev ? "true" : "false");
	xmlTextWriterWriteFormatElement(writer, BAD_CAST "xor", "0x%" PRIx32, crc_params->xor);
	xmlTextWriterEndElement(writer); /* End settings */

	xmlTextWriterStartElement(writer, BAD_CAST "sections");

	/* Output all section CRCs */
	for (name_iter = section_name_list, index = 0u; name_iter; name_iter = sl_list_next(name_iter), index++) {
		section_name = (const char *)name_iter->data;
		xmlTextWriterStartElement(writer, BAD_CAST "crc");
		xmlTextWriterWriteFormatAttribute(writer, BAD_CAST "name", "%s", section_name);
		xmlTextWriterWriteFormatAttribute(writer, BAD_CAST "index", "%zu", index);
		if (elf_patch_get_section_address(ep, section_name, &vma, &len)) {
			print_err("Could not retrieve section address / length of section '%s'. XML output will be faulty.\n",
				  section_name);
		}
		xmlTextWriterWriteFormatAttribute(writer, BAD_CAST "vma", "0x%" PRIx64, vma);
		xmlTextWriterWriteFormatAttribute(writer, BAD_CAST "size", "0x%" PRIx64, len);
		xmlTextWriterWriteFormatRaw(writer, "0x%" PRIx32, crcs[index]);
		xmlTextWriterEndElement(writer); /* End crc */
	}
	xmlTextWriterEndElement(writer); /* End sections */
	xmlTextWriterEndDocument(writer);

	xmlFreeTextWriter(writer);
ret_none:
	return ret;
}
