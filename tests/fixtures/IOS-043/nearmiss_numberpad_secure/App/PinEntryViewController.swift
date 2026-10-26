// Near miss: the PIN field is secure, the one-time code uses a number pad, and "Show password" is a toggle label.
import SwiftUI
import UIKit

final class PinEntryViewController: UIViewController {
    private lazy var pinField: UITextField = {
        let field = UITextField()
        field.placeholder = "Enter your PIN"
        field.isSecureTextEntry = true
        return field
    }()
    private let revealToggle = UITextField()

    override func viewDidLoad() {
        super.viewDidLoad()
        revealToggle.placeholder = "Show password"
        view.addSubview(pinField)
    }
}

struct VerifyView: View {
    @ObservedObject var model: VerifyModel

    var body: some View {
        TextField("Code from SMS", text: $model.otpCode)
            .keyboardType(.numberPad)
            .textContentType(.oneTimeCode)
    }
}
