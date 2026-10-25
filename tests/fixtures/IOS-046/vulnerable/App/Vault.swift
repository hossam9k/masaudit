import Foundation

final class Vault {
    private let folder = FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask)[0]

    func store(_ data: Data) throws {
        try data.write(to: folder.appendingPathComponent("credentials.json"))
    }
}
