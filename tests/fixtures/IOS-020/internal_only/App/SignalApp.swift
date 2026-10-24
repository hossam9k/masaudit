import UIKit

final class SignalApp {
    func showExportDatabaseUI(password: String) {
        guard DebugFlags.internalSettings else { return }
        let sheet = ExportSheet()
        sheet.completion = { _, _, _, _ in
            UIPasteboard.general.string = password
        }
        sheet.present()
    }
}
