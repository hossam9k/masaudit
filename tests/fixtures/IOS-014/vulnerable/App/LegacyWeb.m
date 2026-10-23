#import <WebKit/WebKit.h>

void ConfigureWebView(WKWebView *webView) {
    if (@available(iOS 16.4, *)) {
        webView.inspectable = YES;
    }
}
