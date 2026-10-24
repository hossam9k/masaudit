- (NSData *)hashPassword:(NSData *)password {
    CC_MD5(password.bytes, (CC_LONG)password.length, result);
    return nil;
}
