import Foundation

func cacheAge(_ url: URL) throws -> Date? {
    UserDefaults.standard.set(true, forKey: "seen")
    let values = try url.resourceValues(forKeys: [.contentModificationDateKey])
    _ = ProcessInfo.processInfo.systemUptime
    _ = try url.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey])
    return values.contentModificationDate
}
