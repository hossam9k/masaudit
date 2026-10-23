import AuthenticationServices

enum OAuthConfig {
    static let redirectURI = "acmebank://oauth/callback"
}

@MainActor
final class SignInCoordinator: NSObject {
    func start(authorizeURL: URL) {
        let session = ASWebAuthenticationSession(url: authorizeURL,
                                                 callbackURLScheme: "acmebank") { url, error in
            _ = url
        }
        session.start()
    }
}
