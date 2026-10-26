#import <AdSupport/AdSupport.h>
#import <AppTrackingTransparency/AppTrackingTransparency.h>
void AdID(void (^done)(NSUUID *)) {
    [ATTrackingManager requestTrackingAuthorizationWithCompletionHandler:^(ATTrackingManagerAuthorizationStatus s) {
        done(s == ATTrackingManagerAuthorizationStatusAuthorized ? [[ASIdentifierManager sharedManager] advertisingIdentifier] : nil);
    }];
}
