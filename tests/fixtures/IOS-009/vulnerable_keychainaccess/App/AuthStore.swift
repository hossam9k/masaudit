import Foundation
@preconcurrency import KeychainAccess

final class AuthStore {
    private let keychain = Keychain(service: "com.example.auth")

    func save(token: String) {
        keychain["accessToken"] = token
    }
}
