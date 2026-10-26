// Objective-C: the read-access URL is a local holding the Caches folder.
#import <WebKit/WebKit.h>

@implementation LegacyViewer
- (void)show:(NSURL *)page {
    NSURL *caches = [[NSFileManager defaultManager] URLsForDirectory:NSCachesDirectory inDomains:NSUserDomainMask].firstObject;
    [self.webView loadFileURL:page allowingReadAccessToURL:caches];
}
@end
