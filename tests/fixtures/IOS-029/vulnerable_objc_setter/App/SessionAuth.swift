// Swift: a minutes expression; the leading literal is already non-zero.
import LocalAuthentication

func sessionContext() -> LAContext {
    let context = LAContext()
    context.touchIDAuthenticationAllowableReuseDuration = 5 * 60
    return context
}
