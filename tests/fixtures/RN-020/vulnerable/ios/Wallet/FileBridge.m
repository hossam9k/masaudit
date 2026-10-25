#import <React/RCTBridgeModule.h>

@interface FileBridge : NSObject <RCTBridgeModule>
@end

@implementation FileBridge
RCT_EXPORT_MODULE();

RCT_EXPORT_METHOD(read:(NSString *)path resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  NSString *contents = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
  resolve(contents);
}
@end
