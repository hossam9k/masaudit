// Near miss: the page carries a reset token in a hidden input and offers a passwordless email link; no password input.
#import "LoginPage.h"

@implementation LoginPage

- (void)showIn:(WKWebView *)webView {
    NSString *html = @"<form><input type=\"hidden\" name=\"password_reset_token\"><input type=\"email\" autocomplete=\"username\"></form>";
    [webView loadHTMLString:html baseURL:nil];
}

@end
