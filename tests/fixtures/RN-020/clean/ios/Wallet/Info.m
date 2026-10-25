#import <React/RCTBridgeModule.h>
@implementation Info
RCT_EXPORT_MODULE();
RCT_EXPORT_METHOD(version:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  NSString *path = [[NSBundle mainBundle] pathForResource:@"version" ofType:@"txt"];
  resolve([NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil]);
}
@end
