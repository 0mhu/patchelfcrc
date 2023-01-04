#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xmlIO.h>
#include <libxml/xinclude.h>
#include <libxml/tree.h>
#include <libxml/encoding.h>
#include <libxml/xmlwriter.h>
#include <libxml/xmlreader.h>

#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
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

/**
 * @brief Get the content of a node specified by the xpath \p path
 * @param path Xpath to search for
 * @param xpath_ctx Context
 * @param required Print error if not found
 * @return NULL in case of error
 * @return pointer to newly alloceted string data.
 * @note Pointers retured from this function must be freed using xmlFree()
 */
static const char *get_node_content_from_xpath(const char *path, xmlXPathContextPtr xpath_ctx, bool required)
{
	xmlXPathObjectPtr xpath_obj;
	const char *ret = NULL;

	xpath_obj = xmlXPathEvalExpression(BAD_CAST path, xpath_ctx);
	if (xpath_obj) {
		if (xmlXPathNodeSetIsEmpty(xpath_obj->nodesetval)) {
			if (required)
				print_err("Required XML path %s not found.\n", path);

		} else {
			ret = (const char *)xmlNodeGetContent(xpath_obj->nodesetval->nodeTab[0]);
		}
		xmlXPathFreeObject(xpath_obj);
	} else {
		/* Error */
		print_err("Error searching for path %s in XML. This is an error. Report this.\n", path);
	}

	return ret;
}


/**
 * @brief Convert a number string (either prefixed 0x hex or decimal) to a uint64
 *
 * In case of an error, the \p output remains untouched
 *
 * @param[in] data input data. 0 terminated
 * @param[in] output Converted number.
 * @return 0 if okay
 * @return negative in case of error
 */
static int convert_number_string_to_uint(const char *data, uint64_t *output)
{
	int ret = -1;
	uint64_t num;
	char *endptr;

	if (!data || !output)
		return -1000;

	errno = 0;
	num = strtoull(data, &endptr, 0);
	if (endptr == data) {
		/* Error finding number */
		print_err("Data %s in XML is not a valid number\n", data);
	} else if (errno == ERANGE) {
		print_err("Data %s in XML overflowed\n", data);
	} else if (errno == EINVAL) {
		print_err("Unspecified error converting '%s' to a number\n", data);
	} else if (errno == 0 && data && *endptr != '\0') {
		print_err("Data '%s' could not be fully parsed to a number. Part '%s' is irritating\n", data, endptr);
	} else if (errno == 0 && data && *endptr == '\0') {
		ret = 0;
		*output = num;
	}

	return ret;
}

/**
 * @brief Get the content of an xpath and convert it to a uint64_t
 * @param[in] xpath Path to get content from
 * @param[in] xpath_ctx Xpath context
 * @param[out] output Number output. Remains untouched in case of an error
 * @param required This xpath is required. Will turn on error reporting if it is not found.
 * @return 0 if successful
 * @return negative in case of an error
 */
static int get_uint64_from_xpath_content(const char *xpath, xmlXPathContextPtr xpath_ctx, uint64_t *output, bool required)
{
	const char *data;
	int ret = -1;

	data = get_node_content_from_xpath(xpath, xpath_ctx, required);
	if (data) {
		ret = convert_number_string_to_uint(data, output);
		xmlFree((void *)data);
	}

	return ret;
}

/**
 * @brief Get the content of an xpath and convert it to a uint64_t
 * @param[in] xpath Path to get content from
 * @param[in] xpath_ctx Xpath context
 * @param[out] output Number output. Remains untouched in case of an error
 * @param required This xpath is required. Will turn on error reporting if it is not found.
 * @return 0 if successful
 * @return negative in case of an error
 */
static int get_uint32_from_xpath_content(const char *xpath, xmlXPathContextPtr xpath_ctx, uint32_t *output, bool required)
{
	const char *data;
	uint64_t tmp;
	int ret = -1;

	data = get_node_content_from_xpath(xpath, xpath_ctx, required);
	if (data) {
		ret = convert_number_string_to_uint(data, &tmp);
		xmlFree((void *)data);

		if (ret == 0) {
			if (tmp > UINT32_MAX) {
				ret = -2;
				print_err("Value in XML file at path '%s' is too large for uint32_t\n", xpath);
			} else {
				*output = (uint32_t)tmp;
			}
		}
	}

	return ret;
}


struct xml_crc_import *xml_import_from_file(const char *path)
{
	struct xml_crc_import *ret = NULL;
	xmlDocPtr doc;
	xmlNodePtr root_node, settings_node, crc_node, iter;
	xmlXPathContextPtr xpath_ctx = NULL;
	uint64_t tmp_num64 = 0;
	uint32_t tmp_num32 = 0;
	const char *cptr;

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

	/* Get xpath context */
	xpath_ctx = xmlXPathNewContext(doc);
	if (!xpath_ctx) {
		goto ret_close_doc;
	}

	/* Allocate xml import structure */
	ret = xml_crc_import_alloc();
	if (!ret)
		goto ret_close_doc;


	/* Do not do extensive error handling. It is assured by the schema that the numbers are parsable */
	(void)get_uint64_from_xpath_content("/patchelfcrc/settings/poly", xpath_ctx, &tmp_num64, true);
	ret->crc_config.polynomial = tmp_num64;

	(void)get_uint32_from_xpath_content("/patchelfcrc/settings/start", xpath_ctx, &tmp_num32, true);
	ret->crc_config.start_value = tmp_num32;

	(void)get_uint32_from_xpath_content("/patchelfcrc/settings/xor", xpath_ctx, &tmp_num32, true);
	ret->crc_config.xor = tmp_num32;

	cptr = get_node_content_from_xpath("/patchelfcrc/settings/rev", xpath_ctx, false);
	if (cptr) {
		xmlFree((void *)cptr);
		ret->crc_config.rev = true;
	} else {
		ret->crc_config.rev = false;
	}


	goto ret_close_doc;

ret_dealloc:
	xml_crc_import_free(ret);
	ret = NULL;

ret_close_doc:
	if (xpath_ctx)
		xmlXPathFreeContext(xpath_ctx);

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
