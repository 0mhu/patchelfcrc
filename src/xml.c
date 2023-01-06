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
#include <string.h>
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

int xml_write_crcs_to_file(const char *path, const struct crc_import_data *crc_data)
{
	int ret = 0;
	xmlTextWriter *writer;
	SlList *entry_iter;
	const struct crc_entry *entry;
	size_t index;

	if (!path || !crc_data) {
		return -1000;
	}

	writer = xmlNewTextWriterFilename(path, 0);
	if (!writer) {
		print_err("Cannot create XML file %s\n", path);
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
	xmlTextWriterWriteFormatElement(writer, BAD_CAST "poly", "0x%" PRIx64, crc_data->crc_config.polynomial);
	xmlTextWriterWriteFormatElement(writer, BAD_CAST "start", "0x%" PRIx32, crc_data->crc_config.start_value);
	if (crc_data->crc_config.rev) {
		xmlTextWriterStartElement(writer, BAD_CAST "rev");
		xmlTextWriterEndElement(writer);
	}
	xmlTextWriterWriteFormatElement(writer, BAD_CAST "xor", "0x%" PRIx32, crc_data->crc_config.xor);
	if (crc_data->elf_bits < 0) {
		print_err("Cannot determine ELF class. Generated XML will be faulty.\n");
		ret |= -1;
	}
	xmlTextWriterWriteFormatElement(writer, BAD_CAST "elfclass", "%d", crc_data->elf_bits);
	xmlTextWriterEndElement(writer); /* End settings */

	xmlTextWriterStartElement(writer, BAD_CAST "sections");

	/* Output all section CRCs */
	for (entry_iter = crc_data->crc_entries, index = 0u; entry_iter; entry_iter = sl_list_next(entry_iter), index++) {
		entry = (const struct crc_entry *)entry_iter->data;
		xmlTextWriterStartElement(writer, BAD_CAST "crc");
		xmlTextWriterWriteFormatAttribute(writer, BAD_CAST "name", "%s", entry->name);
		xmlTextWriterWriteFormatAttribute(writer, BAD_CAST "index", "%zu", index);
		xmlTextWriterWriteFormatAttribute(writer, BAD_CAST "vma", "0x%" PRIx64, entry->vma);
		xmlTextWriterWriteFormatAttribute(writer, BAD_CAST "lma", "0x%" PRIx64, entry->lma);
		xmlTextWriterWriteFormatAttribute(writer, BAD_CAST "size", "0x%" PRIx64, entry->size);
		xmlTextWriterWriteFormatRaw(writer, "0x%" PRIx32, entry->crc);
		xmlTextWriterEndElement(writer); /* End crc */
	}
	xmlTextWriterEndElement(writer); /* End sections */

	xmlTextWriterEndElement(writer); /* End root node */

	xmlTextWriterEndDocument(writer);

	xmlFreeTextWriter(writer);
ret_none:
	return ret;
}

struct crc_import_data *xml_crc_import_alloc(void)
{
	struct crc_import_data *ret = NULL;

	ret = (struct crc_import_data *)malloc(sizeof(struct crc_import_data));
	if (ret)
		ret->crc_entries = NULL;
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
 * @return pointer to newly allocated string data.
 * @note Pointers returned from this function must be freed using xmlFree()
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

int get_uint64_from_node_attribute(xmlNodePtr node, const char *attr, uint64_t *output)
{
	xmlChar *data;
	uint64_t num;
	int ret = -1;

	data = xmlGetProp(node, BAD_CAST attr);
	if (data) {
		if (!convert_number_string_to_uint((const char *)data, &num)) {
			ret = 0;
			*output = num;
		}
		xmlFree(data);
	}

	return ret;
}

static int get_uint32_from_node_attribute(xmlNodePtr node, const char *attr, uint32_t *output)
{
	int ret;
	uint64_t tmp = 0;

	ret = get_uint64_from_node_attribute(node, attr, &tmp);

	if (tmp > UINT32_MAX || ret) {
		print_err("Cannot convert attribute %s to 32 bit number\n", attr);
		ret = -1;
	} else {
		*output = (uint32_t)tmp;
	}

	return ret;
}

static int get_uint64_from_node_content(xmlNodePtr node, uint64_t *output)
{
	xmlChar *data;
	int ret = -1;

	data = xmlNodeGetContent(node);

	if (data) {
		ret = convert_number_string_to_uint((const char *)data, output);
		xmlFree(data);
	}

	return ret;
}

static int get_uint32_from_node_content(xmlNodePtr node, uint32_t *output)
{
	int ret;
	uint64_t tmp = 0;

	ret = get_uint64_from_node_content(node, &tmp);

	if (tmp > UINT32_MAX || ret) {
		print_err("Cannot convert content to 32 bit number\n");
		ret = -1;
	} else {
		*output = (uint32_t)tmp;
	}

	return ret;
}


struct crc_import_data *xml_import_from_file(const char *path)
{
	struct crc_import_data *ret = NULL;
	struct crc_entry *crc;
	xmlDocPtr doc;
	xmlNodePtr root_node;
	xmlNodePtr current_node;
	xmlXPathContextPtr xpath_ctx = NULL;
	xmlXPathObjectPtr xpath_obj = NULL;
	uint64_t tmp_num64 = 0;
	uint32_t tmp_num32 = 0;
	int i;
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

	/* Get the version number and print error in case of incompatibility. Continue either way */
	cptr = (char *)xmlGetProp(root_node, BAD_CAST "version");
	if (cptr) {
		if (strncmp(cptr, version_string, strlen(version_string)) != 0) {
			print_err("XML file was generated with another version of patchelfcrc.\n");
			print_err("\t XML shows: %s\n", cptr);
			print_err("\t Program version: %s\n", version_string);
		}
		xmlFree((char *)cptr);
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

	(void)get_uint32_from_xpath_content("/patchelfcrc/settings/elfclass", xpath_ctx, &tmp_num32, true);
	ret->elf_bits = (int)tmp_num32;

	/* Get all CRCs */
	xpath_obj = xmlXPathEvalExpression(BAD_CAST "/patchelfcrc/sections/crc", xpath_ctx);
	if (xmlXPathNodeSetIsEmpty(xpath_obj->nodesetval)) {
		print_err("Internal error during read\n");
		xml_crc_import_free(ret);
		ret = NULL;
		goto ret_close_doc;
	}

	for (i = 0; i < xpath_obj->nodesetval->nodeNr; i++) {
		current_node = xpath_obj->nodesetval->nodeTab[i];
		crc = (struct crc_entry *)malloc(sizeof(struct crc_entry));
		ret->crc_entries = sl_list_append(ret->crc_entries, crc);

		get_uint64_from_node_attribute(current_node, "vma", &tmp_num64);
		crc->vma = tmp_num64;
		get_uint64_from_node_attribute(current_node, "size", &tmp_num64);
		crc->size = tmp_num64;
		get_uint64_from_node_attribute(current_node, "lma", &tmp_num64);
		crc->lma = tmp_num64;
		get_uint32_from_node_content(current_node, &tmp_num32);
		crc->crc = tmp_num32;

		crc->name = (char *)xmlGetProp(current_node, BAD_CAST "name");
	}

ret_close_doc:

	if (xpath_obj)
		xmlXPathFreeObject(xpath_obj);
	if (xpath_ctx)
		xmlXPathFreeContext(xpath_ctx);

	/* Free document and all of its children */
	xmlFreeDoc(doc);

	/* Cleanup global garbage */
	xmlCleanupParser();
ret_none:
	return ret;


}

static void free_crc_entry(void *entry)
{
	struct crc_entry *e = (struct crc_entry *)entry;

	if (entry) {
		if (e->name)
			xmlFree(e->name);
		free(entry);
	}
}

void xml_crc_import_free(struct crc_import_data *data)
{
	if (!data)
		return;

	sl_list_free_full(data->crc_entries, free_crc_entry);
	data->crc_entries = NULL;
	free(data);
}

void xml_print_xsd(void)
{
	printf("%.*s", schema_xsd_len, schema_xsd);
}
