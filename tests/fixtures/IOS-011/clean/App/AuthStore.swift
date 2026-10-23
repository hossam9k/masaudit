import SwiftUI

final class AuthStore {
    func didSignIn(token: String) {
        // Was: UserDefaults.standard.set(token, forKey: "authToken")
        try? storeToken(Data(token.utf8), account: "session")
        UserDefaults.standard.set(true, forKey: "hasLaunchedBefore")
    }

    func didReceivePushToken(_ fcmToken: String) {
        UserDefaults.standard.set(fcmToken, forKey: "FCM_TOKEN")   // push token, not a credential
    }
}

struct SettingsView: View {
    @AppStorage("prefersDarkMode") var dark = false
    var body: some View { Text("Settings") }
}
