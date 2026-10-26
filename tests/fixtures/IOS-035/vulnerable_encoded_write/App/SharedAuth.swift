// The credentials object is encoded and written straight into the App Group container.
import Foundation

struct Credentials: Codable { let user: String; let refreshToken: String }

func share(_ credentials: Credentials) throws {
    guard let group = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: "group.com.shop") else { return }
    try JSONEncoder().encode(credentials).write(to: group.appendingPathComponent("auth.json"))
}
