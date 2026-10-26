// The event's name mentions an address, but no address is sent: the arguments are enum cases.
import Foundation

enum Analytics {}

func promptShown() {
    TelemetryWrapper.recordEvent(category: .action, method: .view, object: .addressAutofillPromptShown)
}
