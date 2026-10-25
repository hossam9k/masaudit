import UIKit

final class LoginAlert {
    func present(on presenter: UIViewController) {
        let alert = UIAlertController(title: "Login", message: nil, preferredStyle: .alert)
        alert.addTextField { tf in
            tf.placeholder = "Username"
        }
        alert.addTextField { tf in
            tf.placeholder = "Password"
            tf.isSecureTextEntry = false
            tf.accessibilityIdentifier = "password_field"
        }
        presenter.present(alert, animated: true)
    }

    func buildPinField() -> UITextField {
        let pinField = UITextField()
        pinField.keyboardType = .numberPad
        pinField.isSecureTextEntry = false
        return pinField
    }
}
