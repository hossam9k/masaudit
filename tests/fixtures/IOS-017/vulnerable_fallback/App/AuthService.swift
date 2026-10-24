import AuthenticationServices

final class AuthService {
    func session(url: URL, host: String, path: String, scheme: String,
                 completion: @escaping ASWebAuthenticationSession.CompletionHandler) -> ASWebAuthenticationSession {
        if #available(iOS 17.4, *) {
            return ASWebAuthenticationSession(url: url, callback: .https(host: host, path: path), completionHandler: completion)
        } else {
            return ASWebAuthenticationSession(url: url, callbackURLScheme: scheme, completionHandler: completion)
        }
    }

    func legacySession(url: URL, completion: @escaping ASWebAuthenticationSession.CompletionHandler) -> ASWebAuthenticationSession {
        ASWebAuthenticationSession(url: url, callbackURLScheme: "myapp", completionHandler: completion)
    }
}
