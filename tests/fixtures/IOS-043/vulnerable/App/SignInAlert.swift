import UIKit

final class SignInAlert {
    func present(on controller: UIViewController) {
        let alert = UIAlertController(title: "Sign in", message: nil, preferredStyle: .alert)
        alert.addTextField(configurationHandler: { (textField: UITextField!) in
            textField.placeholder = "PIN"
        })
        alert.addAction(UIAlertAction(title: "OK", style: .default))
        controller.present(alert, animated: true)
    }
}
