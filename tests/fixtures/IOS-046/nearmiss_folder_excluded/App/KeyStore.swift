// The whole folder is excluded from backup once, when the store is created; every write goes there.
import Foundation

final class KeyStore {
    private let folder: URL

    init() throws {
        var dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("keys", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try dir.setResourceValues(values)
        folder = dir
    }

    func savePrivateKey(_ pem: Data) throws {
        try pem.write(to: folder.appendingPathComponent("private_key.pem"))
    }
}
