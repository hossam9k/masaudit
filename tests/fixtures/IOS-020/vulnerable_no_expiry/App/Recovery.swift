import UIKit

func copyRecoveryKey(_ recoveryKey: String) {
    UIPasteboard.general.setItems([["public.utf8-plain-text": recoveryKey]], options: [.localOnly: true])
}
