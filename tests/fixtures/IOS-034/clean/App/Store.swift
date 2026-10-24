import Foundation

final class Store {
    func save(_ token: Data, db: Data) throws {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        try token.write(to: docs.appendingPathComponent("session_token.json"))
        try db.write(to: docs.appendingPathComponent("vault.sqlite"))
        try db.write(to: docs.appendingPathComponent("Report.pdf"))
    }

    func cache(_ data: Data) throws {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try data.write(to: support.appendingPathComponent("token.json"))
    }
}
