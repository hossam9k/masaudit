import WebKit

@MainActor
final class VoucherBridge: NSObject, WKScriptMessageHandlerWithReply {
    private let redeem: (String) async throws -> Void

    init(redeem: @escaping (String) async throws -> Void) {
        self.redeem = redeem
    }

    func userContentController(_ userContentController: WKUserContentController,
                               didReceive message: WKScriptMessage) async -> (Any?, String?) {
        let origin = message.frameInfo.securityOrigin
        guard message.frameInfo.isMainFrame,
              origin.protocol == "https",
              origin.host == "app.example.com" else { return (nil, "rejected") }

        guard let code = message.body as? String,
              code.range(of: #"^[A-Z0-9]{8}$"#, options: .regularExpression) != nil
        else { return (nil, "invalid") }

        do {
            try await redeem(code)
            return ("received", nil)
        } catch {
            return (nil, "failed")
        }
    }
}
