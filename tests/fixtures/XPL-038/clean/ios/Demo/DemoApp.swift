import SwiftUI
@main struct DemoApp: App { var body: some Scene { WindowGroup { Text("Hi") } } }

let simulator = ProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"] != nil
