// Vulnerable: iOS 16 URL API writes an API key file straight into Documents.
import Foundation

struct ApiKeyStore {
    func save(_ key: String) async throws {
        let url = URL.documentsDirectory.appending(path: "api_key.txt")
        try key.write(to: url, atomically: true, encoding: .utf8)
    }
}
