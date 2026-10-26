// Objective-C implementation that allocates a UIWebView at runtime (header doesn't mention it).
#import "HelpViewController.h"

@implementation HelpViewController
- (void)viewDidLoad {
    [super viewDidLoad];
    UIWebView *web = [[UIWebView alloc] initWithFrame:self.view.bounds];
    [self.view addSubview:web];
}
@end
