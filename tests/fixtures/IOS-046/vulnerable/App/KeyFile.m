#import "KeyFile.h"

@implementation KeyFile

- (void)storeKey:(NSData *)key {
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *path = [docs stringByAppendingPathComponent:@"private_key.pem"];
    [key writeToFile:path atomically:YES];
}

@end
