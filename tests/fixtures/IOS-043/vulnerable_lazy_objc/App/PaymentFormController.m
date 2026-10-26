// Vulnerable: Objective-C card security code field created in code with default keyboard learning.
#import "PaymentFormController.h"

@implementation PaymentFormController

- (void)viewDidLoad {
    [super viewDidLoad];
    UITextField *cvvField = [[UITextField alloc] initWithFrame:CGRectMake(16, 120, 120, 34)];
    cvvField.placeholder = @"CVV";
    [self.view addSubview:cvvField];
}

@end
