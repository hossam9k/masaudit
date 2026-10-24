import Foundation

enum SharedStore {
    static func save(sessionToken: Data) throws {
        guard let group = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: "group.com.example") else { return }
        try sessionToken.write(to: group.appendingPathComponent("auth.json"))
    }
}
