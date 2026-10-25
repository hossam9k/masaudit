import Foundation

// Near miss: the token file is excluded from backup after it is written.
struct SessionStore {
    func save(_ session: Data) throws {
        let support = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                                  appropriateFor: nil, create: true)
        var url = support.appendingPathComponent("session-token.json")
        try session.write(to: url, options: .completeFileProtection)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try url.setResourceValues(values)
    }
}
