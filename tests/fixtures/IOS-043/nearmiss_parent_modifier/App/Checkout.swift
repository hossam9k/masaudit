// The parent view turns autocorrection off for the form it contains, so the card field inherits it.
import SwiftUI

struct PaymentForm: View {
    @State private var cardNumber = ""
    var body: some View {
        TextField("Card number", text: $cardNumber)
    }
}

struct CheckoutScreen: View {
    var body: some View {
        VStack {
            PaymentForm()
        }
        .autocorrectionDisabled()
    }
}
