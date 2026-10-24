import UIKit

final class PassphraseViewController: UIViewController {
    func copyPassphrase(_ passphrase: Passphrase, expireDate: Date) {
        UIPasteboard.general.setItems(
            [[UIPasteboard.typeAutomatic: passphrase.asPassphrase]],
            options: [.expirationDate: expireDate],
        )
    }

    func copyE2E(_ e2ePassphrase: String) {
        UIPasteboard.general.string = e2ePassphrase
    }
}
