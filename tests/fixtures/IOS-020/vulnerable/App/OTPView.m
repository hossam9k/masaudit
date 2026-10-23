#import <UIKit/UIKit.h>

@implementation OTPView
- (void)copyTapped {
    [[UIPasteboard generalPasteboard] setString:self.otpCode];
}
@end
