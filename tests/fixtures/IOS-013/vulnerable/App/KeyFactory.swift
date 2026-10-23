import Security

func makeAccess() -> SecAccessControl? {
    SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                    [.privateKeyUsage, .biometryAny], nil)
}
