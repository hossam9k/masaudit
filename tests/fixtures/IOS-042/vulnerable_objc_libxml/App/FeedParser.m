// Vulnerable: Objective-C NSXMLParser turns on external entity resolution through the setter.
#import "FeedParser.h"

@implementation FeedParser

- (BOOL)parseFeed:(NSData *)data {
    NSXMLParser *parser = [[NSXMLParser alloc] initWithData:data];
    parser.delegate = self;
    [parser setShouldResolveExternalEntities:YES];
    return [parser parse];
}

@end
