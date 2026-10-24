#import <LocalAuthentication/LocalAuthentication.h>

@implementation LegacyLock
- (void)unlock {
    LAContext *ctx = [[LAContext alloc] init];
    [ctx evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics localizedReason:@"Unlock" reply:^(BOOL ok, NSError *e) { if (ok) [self unlockUI]; }];
}
@end
