import Foundation

struct SessionStore {
    func save(_ session: Data) throws {
        let fileName = "session-token.json"
        let support = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                                  appropriateFor: nil, create: true)
        try session.write(to: support.appendingPathComponent(fileName), options: .completeFileProtection)
    }
}
