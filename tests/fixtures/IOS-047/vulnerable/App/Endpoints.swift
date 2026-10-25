import Foundation

enum Endpoints {
    static let accounts = URL(string: "https://api.example.com/v1/accounts")!
    // A second backend that NSPinnedDomains doesn't list.
    static let payments = URL(string: "https://payments.example.net/v1/transfers")!
    // Two levels below the pinned domain: NSIncludesSubdomains covers only one.
    static let uploads = URL(string: "https://eu.files.api.example.com/upload")!
}

func fetchAccounts() {
    URLSession.shared.dataTask(with: Endpoints.accounts) { _, _, _ in }.resume()
}
