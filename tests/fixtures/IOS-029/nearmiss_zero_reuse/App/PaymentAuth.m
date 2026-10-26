// Near miss: Objective-C setter with zero.
#import <LocalAuthentication/LocalAuthentication.h>

void ResetReuse(LAContext *context) {
    [context setTouchIDAuthenticationAllowableReuseDuration:0];
}
