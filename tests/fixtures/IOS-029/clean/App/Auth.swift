import LocalAuthentication

func makeContext(reuse: TimeInterval) -> LAContext {
    let context = LAContext()
    context.touchIDAuthenticationAllowableReuseDuration = TimeInterval(0)
    context.touchIDAuthenticationAllowableReuseDuration = 0
    context.touchIDAuthenticationAllowableReuseDuration = reuse      // unknown at scan time
    return context
}
