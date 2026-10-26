// Near miss: the Objective-C security code field is secure entry on a number pad.
#import "PaymentFormController.h"

@implementation PaymentFormController

- (void)viewDidLoad {
    [super viewDidLoad];
    UITextField *cvvField = [[UITextField alloc] initWithFrame:CGRectMake(16, 120, 120, 34)];
    cvvField.placeholder = @"CVV";
    [cvvField setSecureTextEntry:YES];
    cvvField.keyboardType = UIKeyboardTypeNumberPad;
    [self.view addSubview:cvvField];
}

@end
