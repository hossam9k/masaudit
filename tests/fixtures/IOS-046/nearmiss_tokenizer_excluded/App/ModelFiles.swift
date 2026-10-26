// Near miss: a tokenizer vocabulary (not a secret) in Application Support, and an API key file in the temporary directory.
import Foundation

struct ModelFiles {
    func saveVocabulary(_ data: Data) throws {
        let url = URL.applicationSupportDirectory.appending(path: "tokenizer.json")
        try data.write(to: url, options: .atomic)
    }

    func stageKey(_ key: String) throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("api_key.txt")
        try key.write(to: url, atomically: true, encoding: .utf8)
    }
}
