// The plain handlers are stubs: one logs an unexpected message, one is empty because the reply-handler
// overload (not shown) does the work.
import WebKit
import os

extension SubscriptionPagesUserScript: WKScriptMessageHandler {
    public func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        Logger.subscription.fault("SubscriptionPagesUserScript sent an unsupported message: \(message.name)")
    }
}

final class MediaCaptureUserScript: NSObject, WKScriptMessageHandler {
    func userContentController(_ userContentController: WKUserContentController,
                               didReceive message: WKScriptMessage) {
        // This script uses the reply-handler overload on every supported iOS version.
    }
}
