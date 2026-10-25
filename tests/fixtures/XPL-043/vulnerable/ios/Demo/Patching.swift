import UIKit

final class Patching: UIViewController {
    @IBOutlet var usernameTextField: UITextField!
    @IBOutlet var passwordTextField: UITextField!

    func login() -> Bool {
        return usernameTextField.text == "admin13412" && passwordTextField.text == "S@g@rm@7h@8848"
    }
}
