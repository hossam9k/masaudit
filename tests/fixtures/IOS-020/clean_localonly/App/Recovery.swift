import UIKit
import UniformTypeIdentifiers

func copyRecoveryKey(_ recoveryKey: String, exp: Date) {
    UIPasteboard.general.setItems([[UTType.plainText.identifier: recoveryKey]], options: [.localOnly: true, .expirationDate: exp])
}

func copyUsername(_ username: String) {
    UIPasteboard.general.string = username
}
