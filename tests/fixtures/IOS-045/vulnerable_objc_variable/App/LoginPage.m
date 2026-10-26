// Vulnerable: Objective-C builds the sign-in page in an NSString variable, then loads it into the web view.
#import "LoginPage.h"

@implementation LoginPage

- (void)showIn:(WKWebView *)webView {
    NSString *html = @"<form action=\"/session\"><input name=\"user\"><input type=\"password\" name=\"pass\"></form>";
    [webView loadHTMLString:html baseURL:[NSURL URLWithString:@"https://accounts.example.com"]];
}

@end
