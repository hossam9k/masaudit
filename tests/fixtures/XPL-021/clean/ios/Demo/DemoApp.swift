import SwiftUI
@main struct DemoApp: App { var body: some Scene { WindowGroup { Text("Hi") } } }

func jailbroken() -> Bool { FileManager.default.fileExists(atPath: "/Applications/Cydia.app") }
