// Near miss: reuse disabled (0.0 / .zero), only compared or read, and a long window only in a DEBUG build.
import LocalAuthentication

func paymentContext() -> LAContext {
    let context = LAContext()
    context.touchIDAuthenticationAllowableReuseDuration = 0.0
    context.touchIDAuthenticationAllowableReuseDuration = .zero
    if context.touchIDAuthenticationAllowableReuseDuration == 30 { assertionFailure("reuse must stay off") }
    let window = context.touchIDAuthenticationAllowableReuseDuration
    print("reuse window", window)
#if DEBUG
    context.touchIDAuthenticationAllowableReuseDuration = 300   // simulator convenience
#endif
    return context
}
