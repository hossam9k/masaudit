import Foundation

// Near misses: a non-secret file in Documents, and a token file in Caches (never backed up).
struct Exports {
    func saveReport(_ data: Data) throws {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        try data.write(to: docs.appendingPathComponent("monthly-report.pdf"))
    }
}

struct TokenCache {
    func save(_ data: Data) throws {
        let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        try data.write(to: caches.appendingPathComponent("token-cache.json"))
    }
}
