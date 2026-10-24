import UIKit

protocol PasscodeDelegate: AnyObject {
    func evaluatePolicy(_ vc: UIViewController, isCorrectCode: Bool)
}

final class PasscodeViewController: UIViewController {
    weak var delegate: PasscodeDelegate?
    func check(_ ok: Bool) {
        self.delegate?.evaluatePolicy(self, isCorrectCode: ok)
    }
}
