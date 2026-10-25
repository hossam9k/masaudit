import Foundation

// Near miss: reads the protection class and compares it; nothing is written with it.
func isUnprotected(_ url: URL) throws -> Bool {
    let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
    let level = attributes[.protectionKey] as? FileProtectionType
    if level == FileProtectionType.none { return true }
    switch level {
    case FileProtectionType.none?: return true
    default: return FileProtectionType.none == level
    }
}
