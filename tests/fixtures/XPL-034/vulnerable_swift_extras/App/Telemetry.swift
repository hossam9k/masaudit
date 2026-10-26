// The event carries the user's email address in its extras.
import Foundation

enum Analytics {}

func signedIn(user: User) {
    TelemetryWrapper.recordEvent(category: .action, method: .tap, object: .signIn, extras: ["email": user.email])
}
