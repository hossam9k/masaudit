import Foundation

// Near misses: the pinned host, one subdomain below it, a legal page and an App Store link.
enum Endpoints {
    static let accounts = URL(string: "https://api.example.com/v1/accounts")!
    static let images = URL(string: "https://cdn.api.example.com/avatars")!
    static let privacy = URL(string: "https://www.example.net/privacy")!
    static let store = URL(string: "https://apps.apple.com/app/id000000")!
}

func fetchAccounts() {
    URLSession.shared.dataTask(with: Endpoints.accounts) { _, _, _ in }.resume()
}
