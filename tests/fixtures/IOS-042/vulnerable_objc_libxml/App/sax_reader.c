/* Vulnerable: libxml2 SAX reader that turns on global entity substitution before parsing. */
#include <libxml/parser.h>

xmlDocPtr read_config(const char *path) {
    xmlSubstituteEntitiesDefault(1);
    return xmlReadFile(path, NULL, 0);
}
