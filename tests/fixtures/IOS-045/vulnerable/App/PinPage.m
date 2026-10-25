#import "PinPage.h"

@implementation PinPage

- (void)showIn:(WKWebView *)webView {
    [webView loadHTMLString:@"<form><input type='password' name='pin'></form>" baseURL:nil];
}

@end
