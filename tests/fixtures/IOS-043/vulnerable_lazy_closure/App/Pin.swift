// A field built in a lazy closure: one field, so one finding (not one for the closure and one for its local).
import UIKit
final class PinViewController: UIViewController {
    lazy var pinField: UITextField = {
        let field = UITextField()
        field.placeholder = "Enter your PIN"
        return field
    }()
}
