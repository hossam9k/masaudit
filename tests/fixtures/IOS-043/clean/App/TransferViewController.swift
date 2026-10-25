import UIKit

final class TransferViewController: UIViewController {
    @IBOutlet private var accountField: UITextField!

    override func viewDidLoad() {
        super.viewDidLoad()
        // The storyboard field is configured here.
        accountField.autocorrectionType = .no
    }
}
