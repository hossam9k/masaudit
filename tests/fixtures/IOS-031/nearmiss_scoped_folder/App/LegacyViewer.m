// Near miss: Objective-C narrows Caches to the folder that holds the page.
#import <WebKit/WebKit.h>

@implementation LegacyViewer
- (void)show:(NSString *)name {
    NSURL *pages = [[[NSFileManager defaultManager] URLsForDirectory:NSCachesDirectory inDomains:NSUserDomainMask].firstObject URLByAppendingPathComponent:@"pages" isDirectory:YES];
    [self.webView loadFileURL:[pages URLByAppendingPathComponent:name] allowingReadAccessToURL:pages];
}
@end
