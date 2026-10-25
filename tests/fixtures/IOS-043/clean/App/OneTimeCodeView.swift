import SwiftUI

struct OneTimeCodeView: View {
    @State private var otp = ""

    var body: some View {
        Form {
            TextField("One-time code", text: $otp)
        }
        .autocorrectionDisabled()
    }
}
