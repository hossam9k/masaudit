import SwiftUI
@main struct DemoApp: App { var body: some Scene { WindowGroup { Text("Hi") } } }

func locked() -> Bool { LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil) }
