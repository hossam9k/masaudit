- (NSString *)pem:(NSMutableString *)result {
    [result insertString: @"-----BEGIN PRIVATE KEY-----\n" atIndex: 0];
    return result;
}
