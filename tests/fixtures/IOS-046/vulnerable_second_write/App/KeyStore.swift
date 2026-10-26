// The cache write is excluded from backup; the private key written by the other function is not.
import Foundation

final class KeyStore {
    func saveCache(_ data: Data) throws {
        var url = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("feed-cache.json")
        try data.write(to: url)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try url.setResourceValues(values)
    }

    func savePrivateKey(_ pem: Data) throws {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        try pem.write(to: docs.appendingPathComponent("private_key.pem"))
    }
}
