import SwiftUI
import UIKit

// Near misses: each sensitive field is secure, has autocorrection off, or uses a number pad.
final class SignInAlert {
    let cardNumberField = UITextField()
    let usernameField = UITextField()

    func present(on controller: UIViewController) {
        let alert = UIAlertController(title: "Sign in", message: nil, preferredStyle: .alert)
        alert.addTextField { field in
            field.placeholder = "Password"
            field.isSecureTextEntry = true
        }
        alert.addTextField { field in
            field.placeholder = "Password hint"
        }
        cardNumberField.placeholder = "Card number"
        cardNumberField.autocorrectionType = .no
        cardNumberField.spellCheckingType = .no
        usernameField.placeholder = "Username"
        controller.present(alert, animated: true)
    }
}

struct PasswordView: View {
    @State private var password = ""
    @State private var isRevealed = false

    var body: some View {
        if isRevealed {
            TextField("Password", text: $password)
        } else {
            SecureField("Password", text: $password)
        }
    }
}
