import AuthenticationServices

extension GlobalModalCoordinator: SyncWithBrowserProcessorDelegate {
    func performWebAuthSession(url: URL) async -> URL? {
        await withCheckedContinuation { continuation in
            let session = ASWebAuthenticationSession(
                url: url,
                callbackURLScheme: "acmebank",
            ) { callbackURL, _ in
                continuation.resume(returning: callbackURL)
            }
            session.prefersEphemeralWebBrowserSession = false
            session.start()
        }
    }
}
