import UIKit

final class LoginAlert {
    var passwordField = UITextField()

    func present(on presenter: UIViewController) {
        let alert = UIAlertController(title: "Login", message: nil, preferredStyle: .alert)
        alert.addTextField { tf in
            tf.placeholder = "Username"
            tf.isSecureTextEntry = false
        }
        alert.addTextField { tf in
            tf.placeholder = "Password"
            tf.isSecureTextEntry = true
        }
        presenter.present(alert, animated: true)
    }

    // A show-password button the user taps on purpose.
    @objc func togglePasswordVisibility() {
        passwordField.isSecureTextEntry = false
    }

    func update(showing: Bool) {
        if showing {
            passwordField.isSecureTextEntry = false
        } else {
            passwordField.isSecureTextEntry = true
        }
    }
}
