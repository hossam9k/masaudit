import AuthenticationServices

enum Links {
    static let product = "acmebank://product/42"             // in-app navigation, not auth
    static let google = "com.googleusercontent.apps.1234-abcd://oauth2redirect"
    // Old redirect, replaced: "acmebank://oauth/callback"
}

@MainActor
final class SignInCoordinator: NSObject {
    func start(authorizeURL: URL) {
        let session = ASWebAuthenticationSession(
            url: authorizeURL,
            callback: .https(host: "auth.example.com", path: "/oauth/callback")
        ) { url, _ in _ = url }
        session.start()
    }

    func startLegacyWithoutCallback(authorizeURL: URL) {
        let session = ASWebAuthenticationSession(url: authorizeURL, callbackURLScheme: nil) { _, _ in }
        session.start()
    }
}
