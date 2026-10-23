import Foundation

// TODO: evaluate TrustKit or NSPinnedDomains before launch.
struct BalanceAPI {
    let session = URLSession(configuration: .default)

    func balance() async throws -> Data {
        let (data, _) = try await session.data(from: URL(string: "https://api.example.com/balance")!)
        return data
    }
}
