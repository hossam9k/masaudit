// Vulnerable: Objective-C event upload to a tracking host the privacy manifest doesn't list.
#import "MixpanelBridge.h"

@implementation MixpanelBridge

- (NSURL *)trackURL {
    return [NSURL URLWithString:@"https://api-eu.mixpanel.com/track"];
}

@end
