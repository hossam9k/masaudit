import Foundation

final class ClassicAppManager {
    let groupID = "group.com.example.classic"

    func loadAccounts() throws -> Any? {
        guard let url = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: groupID) else {
            return nil
        }
        return try ClassicAppAccountManager(cacheFolder: url).loadUsers()
    }
}
