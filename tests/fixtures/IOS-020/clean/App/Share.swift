import UIKit

func copyShareLink(_ shareLink: URL) {
    UIPasteboard.general.url = shareLink
}
