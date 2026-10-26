// Near miss: entity resolution stays off; the dangerous option names appear only in a comment and a string.
#import "FeedParser.h"

@implementation FeedParser

- (BOOL)parseFeed:(NSData *)data {
    NSXMLParser *parser = [[NSXMLParser alloc] initWithData:data];
    parser.delegate = self;
    // Never call [parser setShouldResolveExternalEntities:YES] here (XXE).
    [parser setShouldResolveExternalEntities:NO];
    NSLog(@"XML_PARSE_NOENT and XML_PARSE_DTDLOAD are disabled");
    return [parser parse];
}

@end
