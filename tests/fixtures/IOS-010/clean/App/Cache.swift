import Foundation

// Don't use .noFileProtection here: the receipts are sensitive.
func cache(_ data: Data, at url: URL) throws {
    try data.write(to: url, options: [.atomic, .completeFileProtection])
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
    var fileURL = url
    try fileURL.setResourceValues(values)
}
