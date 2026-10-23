import WebKit

final class PaymentBridge: NSObject, WKScriptMessageHandler {
    func userContentController(_ userContentController: WKUserContentController,
                               didReceive message: WKScriptMessage) {
        guard let body = message.body as? [String: Any],
              let amount = body["amount"] as? Int else { return }
        PaymentService.shared.pay(amount: amount)
    }
}
