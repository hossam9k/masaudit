#import <Security/Security.h>

SecAccessControlRef MakeAccess(void) {
    return SecAccessControlCreateWithFlags(kCFAllocatorDefault,
        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryAny, NULL);
}
