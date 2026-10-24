import AuthenticationServices

enum Links {
    static let newItem = "myapp://authenticator/newItem"
}

final class Donations {
    func confirm3DS(stripe3DSURL: URL) {
        let s = ASWebAuthenticationSession(url: stripe3DSURL, callbackURLScheme: Stripe.SCHEME_FOR_3DS) { _, _ in }
        s.start()
    }

    func performCheckoutWebAuthSession(url: URL) {
        let s = ASWebAuthenticationSession(url: url, callbackURLScheme: billing.checkoutCallbackUrlScheme) { _, _ in }
        s.start()
    }
}
