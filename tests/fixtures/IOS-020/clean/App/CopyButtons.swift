import UIKit
import UniformTypeIdentifiers

func copyPassword(_ password: String) {
    // Not UIPasteboard.general.string = password: it would sync through Universal Clipboard.
    UIPasteboard.general.setItems(
        [[UTType.plainText.identifier: password]],
        options: [
            .localOnly: true,
            .expirationDate: Date().addingTimeInterval(60)
        ]
    )
}
