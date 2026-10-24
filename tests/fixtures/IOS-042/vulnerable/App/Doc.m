#include <libxml/parser.h>
void Parse(const char *buf, int len) {
    xmlReadMemory(buf, len, NULL, NULL, XML_PARSE_NOENT | XML_PARSE_DTDLOAD);
}
