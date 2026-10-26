// Objective-C with an allowlist: only the app's own host reaches the web view.
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) WKWebView *webView;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)app openURL:(NSURL *)url options:(NSDictionary<UIApplicationOpenURLOptionsKey, id> *)options {
    if (![url.host isEqualToString:@"shop.example.com"]) {
        return NO;
    }
    [self.webView loadRequest:[NSURLRequest requestWithURL:url]];
    return YES;
}
@end
