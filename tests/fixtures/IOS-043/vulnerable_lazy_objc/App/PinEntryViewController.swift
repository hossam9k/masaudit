// Vulnerable: a lazily built UIKit PIN field and a SwiftUI one-time-code field bound to a view model, both learnable.
import SwiftUI
import UIKit

final class PinEntryViewController: UIViewController {
    private lazy var pinField: UITextField = {
        let field = UITextField()
        field.borderStyle = .roundedRect
        field.textAlignment = .center
        return field
    }()

    override func viewDidLoad() {
        super.viewDidLoad()
        pinField.placeholder = "Enter your PIN"
        view.addSubview(pinField)
    }
}

struct VerifyView: View {
    @ObservedObject var model: VerifyModel

    var body: some View {
        TextField("Code from SMS", text: $model.otpCode)
    }
}
