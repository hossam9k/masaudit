import SwiftUI
@main struct DemoApp: App { var body: some Scene { WindowGroup { Text("Hi") } } }

func traced() -> Bool { var info = kinfo_proc(); return (info.kp_proc.p_flag & P_TRACED) != 0 }
