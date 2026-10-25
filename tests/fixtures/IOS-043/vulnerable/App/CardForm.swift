import SwiftUI
import UIKit

final class CardFormController: UIViewController {
    let cardNumberField = UITextField()

    override func viewDidLoad() {
        super.viewDidLoad()
        cardNumberField.placeholder = "Card number"
        view.addSubview(cardNumberField)
    }
}

struct SecurityCodeView: View {
    @State private var cvv = ""

    var body: some View {
        Form {
            TextField("Security code", text: $cvv)
        }
    }
}
