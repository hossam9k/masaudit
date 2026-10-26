// The pre-iOS 11.3 Objective-C name of the same flag.
#import <Security/Security.h>

SecAccessControlRef LegacyAccess(void) {
    return SecAccessControlCreateWithFlags(NULL, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                           kSecAccessControlTouchIDAny, NULL);
}
