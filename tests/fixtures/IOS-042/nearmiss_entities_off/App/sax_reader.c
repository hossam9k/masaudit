/* Near miss: libxml2 reads with network access off and entity substitution left at its default (0). */
#include <libxml/parser.h>

xmlDocPtr read_config(const char *path) {
    xmlSubstituteEntitiesDefault(0);
    return xmlReadFile(path, NULL, XML_PARSE_NONET | XML_PARSE_NOBLANKS);
}
