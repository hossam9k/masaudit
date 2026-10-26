// Objective-C: setter call with the maximum constant, and dot syntax with a fractional value.
#import <LocalAuthentication/LocalAuthentication.h>

LAContext *PaymentContext(void) {
    LAContext *context = [[LAContext alloc] init];
    [context setTouchIDAuthenticationAllowableReuseDuration:LATouchIDAuthenticationMaximumAllowableReuseDuration];
    return context;
}

LAContext *TransferContext(void) {
    LAContext *context = [[LAContext alloc] init];
    context.touchIDAuthenticationAllowableReuseDuration = 0.5;
    return context;
}
