import LocalAuthentication

func makeContext() -> LAContext {
    let context = LAContext()
    context.touchIDAuthenticationAllowableReuseDuration = 30
    let other = LAContext()
    other.touchIDAuthenticationAllowableReuseDuration = LATouchIDAuthenticationMaximumAllowableReuseDuration
    return context
}
