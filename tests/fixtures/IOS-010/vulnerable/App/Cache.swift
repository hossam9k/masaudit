import Foundation

func cache(_ data: Data, at url: URL) throws {
    try data.write(to: url, options: [.atomic, .noFileProtection])
    try FileManager.default.setAttributes([.protectionKey: FileProtectionType.none], ofItemAtPath: url.path)
}
