import Foundation

class ClassicAppAccountManager {
    private let cacheFolder: URL

    init(cacheFolder: URL) {
        self.cacheFolder = cacheFolder
    }

    func loadUsers() throws -> Any? {
        let fileContent = try Data(contentsOf: cacheFolder.appending(component: "users"))
        let decoder = try NSKeyedUnarchiver(forReadingFrom: fileContent)
        decoder.requiresSecureCoding = false
        return decoder.decodeObject(forKey: NSKeyedArchiveRootObjectKey)
    }
}
