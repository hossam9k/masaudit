// Vulnerable: Objective-C CFStream socket pair to a public host on port 80 with no SSL settings.
#import "TickerStream.h"

@implementation TickerStream

- (void)connect {
    CFReadStreamRef readStream;
    CFWriteStreamRef writeStream;
    CFStreamCreatePairWithSocketToHost(NULL, (__bridge CFStringRef)@"ticker.example.com", 80, &readStream, &writeStream);
    CFReadStreamOpen(readStream);
    CFWriteStreamOpen(writeStream);
}

@end
