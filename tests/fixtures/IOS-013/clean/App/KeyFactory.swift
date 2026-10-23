import Security

func makeAccess() -> SecAccessControl? {
    SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                    [.privateKeyUsage, .biometryCurrentSet], nil)   // not .biometryAny
}
