// Objective-C block-list: one host is refused, every other one is loaded.
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>

@interface HandoffDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) WKWebView *webView;
@end

@implementation HandoffDelegate
- (BOOL)application:(UIApplication *)app continueUserActivity:(NSUserActivity *)activity restorationHandler:(void (^)(NSArray *))handler {
    if ([activity.webpageURL.host isEqualToString:@"ads.example.com"]) { return NO; }
    NSURL *link = activity.webpageURL;
    [self.webView loadRequest:[NSURLRequest requestWithURL:link]];
    return YES;
}
@end
