#include <libxml/parser.h>
#include <libxml/xmlIO.h>
#include <libxml/xinclude.h>
#include <libxml/tree.h>
#include <libxml/encoding.h>
#include <libxml/xmlwriter.h>
#include <libxml/xmlreader.h>

#include <stdint.h>
#include <inttypes.h>
#include <patchelfcrc/reporting.h>
#include <patchelfcrc/xml.h>
#include <patchelfcrc/version.h>
#include <generated/schema-blob.h>

void xml_init(void)
{
	LIBXML_TEST_VERSION;
}

int xml_write_crcs_to_file(const char *path, const uint32_t *crcs, SlList *section_name_list,
			   const struct crc_settings *crc_params, elfpatch_handle_t *ep)
{
	int ret = 0;
	int bitsize;
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
	/* Generate the root node */
	xmlTextWriterStartElement(writer, BAD_CAST "patchelfcrc");
	xmlTextWriterWriteFormatAttribute(writer, BAD_CAST "version", "%s", version_string);

	xmlTextWriterStartElement(writer, BAD_CAST "settings");
	xmlTextWriterWriteFormatElement(writer, BAD_CAST "poly", "0x%" PRIx64, crc_params->polynomial);
	xmlTextWriterWriteFormatElement(writer, BAD_CAST "start", "0x%" PRIx32, crc_params->start_value);
	if (crc_params->rev) {
		xmlTextWriterStartElement(writer, BAD_CAST "rev");
		xmlTextWriterEndElement(writer);
	}
	xmlTextWriterWriteFormatElement(writer, BAD_CAST "xor", "0x%" PRIx32, crc_params->xor);
	bitsize = elf_patch_get_bits(ep);
	if (bitsize < 0) {
		print_err("Cannot determine ELF class. Generated XML will be faulty.\n");
		ret |= -1;
	}
	xmlTextWriterWriteFormatElement(writer, BAD_CAST "elfclass", "%d", bitsize);
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
			ret |= -1;
		}
		xmlTextWriterWriteFormatAttribute(writer, BAD_CAST "vma", "0x%" PRIx64, vma);
		xmlTextWriterWriteFormatAttribute(writer, BAD_CAST "size", "0x%" PRIx64, len);
		xmlTextWriterWriteFormatRaw(writer, "0x%" PRIx32, crcs[index]);
		xmlTextWriterEndElement(writer); /* End crc */
	}
	xmlTextWriterEndElement(writer); /* End sections */

	xmlTextWriterEndElement(writer); /* End root node */

	xmlTextWriterEndDocument(writer);

	xmlFreeTextWriter(writer);
ret_none:
	return ret;
}

static struct xml_crc_import *xml_crc_import_alloc(void)
{
	struct xml_crc_import *ret = NULL;

	ret = (struct xml_crc_import *)malloc(sizeof(struct xml_crc_import));
	if (ret)
		ret->xml_crc_entries = NULL;
	else
		print_err("Error. Out of memory. This should never happen\n");

	return ret;
}

static void recusive_node_iter(xmlNodePtr node, int level)
{
	int i;
	xmlNodePtr iter;
	xmlAttrPtr attr;
	xmlChar *t;

	for (i = level; i > 0; i--)
		printf("    ");

	if (node->content)
		printf("Node <%s> (%d) >%s<", node->name, node->type, node->content);
	else
		printf("Node <%s> (%d)", node->name, node->type);
	if (node->properties) {
		for (attr = node->properties; attr; attr = attr->next) {
			t = xmlNodeListGetString(node->doc, attr->children, 1);
			printf(" %s=\"%s\"", attr->name, t);
			xmlFree(t);
		}
	}
	printf("\n");
	for (iter = node->children; iter; iter = iter->next) {
		recusive_node_iter(iter, level + 1);
	}
}

static bool validate_xml_doc(xmlDocPtr doc)
{
	bool ret = false;
	xmlSchemaParserCtxtPtr parser_ctx = NULL;
	xmlSchemaPtr schema = NULL;
	xmlSchemaValidCtxtPtr validation_ctx = NULL;
	int res;

	parser_ctx = xmlSchemaNewMemParserCtxt((const char *)schema_xsd, schema_xsd_len);
	if (!parser_ctx) {
		print_err("Cannot create parse context for built-in XSD. This is a bug. Report this.\n");
		goto ret_none;
	}

	schema = xmlSchemaParse(parser_ctx);
	if (!schema) {
		print_err("Cannot parse built-in XSD. This is a bug. Report this.\n");
		goto ret_none;
	}

	validation_ctx = xmlSchemaNewValidCtxt(schema);
	if (!validation_ctx) {
		print_err("Cannot create validation context. This is a bug. Report this.\n");
		goto ret_none;
	}

	res = xmlSchemaValidateDoc(validation_ctx, doc);
	ret = (res == 0 ? true : false);

ret_none:
	/* Clean up */
	if (validation_ctx)
		xmlSchemaFreeValidCtxt(validation_ctx);
	if (schema)
		xmlSchemaFree(schema);
	if (parser_ctx)
		xmlSchemaFreeParserCtxt(parser_ctx);
	return ret;
}

struct xml_crc_import *xml_import_from_file(const char *path)
{
	struct xml_crc_import *ret = NULL;
	xmlDocPtr doc;
	xmlNodePtr root_node, settings_node, crc_node, iter;

	if (!path)
		return NULL;

	doc = xmlReadFile(path, NULL, 0);
	if (!doc) {
		print_err("Error reading XML file: %s\n", path);
		goto ret_none;
	}
	root_node = xmlDocGetRootElement(doc);
	if (!root_node) {
		goto ret_close_doc;
	}

	/* Validate the document */
	if (!validate_xml_doc(doc)) {
		print_err("XML does not match expected format. Cannot import.\n");
		goto ret_close_doc;
	}

	/* Allocate xml import structure */
	ret = xml_crc_import_alloc();
	if (!ret)
		goto ret_close_doc;

	recusive_node_iter(root_node, 0);


ret_close_doc:
	/* Free document and all of its children */
	xmlFreeDoc(doc);

	/* Cleanup global garbage */
	xmlCleanupParser();
ret_none:
	return ret;
}

static void free_xml_crc_entry(void *entry) {
	if (entry)
		free(entry);
}

void xml_crc_import_free(struct xml_crc_import *data)
{
	if (!data)
		return;

	sl_list_free_full(data->xml_crc_entries, free_xml_crc_entry);
	data->xml_crc_entries = NULL;
	free(data);
}

void xml_print_xsd(void)
{
	printf("%.*s", schema_xsd_len, schema_xsd);
}
