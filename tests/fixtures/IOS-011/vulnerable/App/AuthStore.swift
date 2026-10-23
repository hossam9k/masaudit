import SwiftUI

final class AuthStore {
    func didSignIn(token: String) {
        UserDefaults.standard.set(token, forKey: "authToken")
    }
}

struct SettingsView: View {
    @AppStorage("refresh_token") var refreshToken: String = ""
    var body: some View { Text("Settings") }
}
