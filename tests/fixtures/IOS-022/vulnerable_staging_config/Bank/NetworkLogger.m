// Objective-C import of a debug tool in a shipping source file, with no #if DEBUG guard.
#import <UIKit/UIKit.h>
#import <FlipperKit/FlipperClient.h>

void StartFlipper(UIApplication *app) {
    [[FlipperClient sharedClient] start];
}
