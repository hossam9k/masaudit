// Clears the entity and DTD flags with a mask: the parser never resolves entities.
#include <libxml/parser.h>
static int SafeOptions(int options) {
    options &= ~(XML_PARSE_NOENT | XML_PARSE_DTDLOAD);
    return options | XML_PARSE_NONET;
}
