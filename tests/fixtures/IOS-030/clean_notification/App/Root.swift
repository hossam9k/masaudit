import UIKit

final class Root: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        NotificationCenter.default.addObserver(self, selector: #selector(hideContent), name: UIApplication.willResignActiveNotification, object: nil)
    }
    @objc private func hideContent() {
        view.isHidden = true
    }
}
