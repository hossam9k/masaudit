#import <Security/Security.h>

static NSDictionary *ItemAttributes(NSData *secret) {
    return @{ (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
              (__bridge id)kSecValueData: secret,
              (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAlwaysThisDeviceOnly };
}
