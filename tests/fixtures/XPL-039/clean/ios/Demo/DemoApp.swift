import SwiftUI
@main struct DemoApp: App { var body: some Scene { WindowGroup { Text("Hi") } } }

func hooked() -> Bool { (0..<_dyld_image_count()).contains { String(cString: _dyld_get_image_name($0)).contains("Frida") } }
