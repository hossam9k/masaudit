import Foundation

func loadAccounts(fileContent: Data, key: Data) throws -> Any? {
    let plain = try AES.decrypt(fileContent, key: key)
    let decoder = try NSKeyedUnarchiver(forReadingFrom: plain)
    decoder.requiresSecureCoding = false
    return decoder.decodeObject(forKey: "accounts")
}
