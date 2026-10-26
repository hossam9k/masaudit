// The handler evaluates trust through a helper in the same file, and a Ktor block evaluates before answering.
package com.bank.net

import io.ktor.client.engine.darwin.DarwinClientEngineConfig
import platform.Foundation.*
import platform.Security.SecTrustEvaluateWithError
import platform.Security.SecTrustRef
import platform.darwin.NSObject

class PinnedDelegate : NSObject(), NSURLSessionDelegateProtocol {
    override fun URLSession(
        session: NSURLSession,
        didReceiveChallenge: NSURLAuthenticationChallenge,
        completionHandler: (NSURLSessionAuthChallengeDisposition, NSURLCredential?) -> Unit,
    ) {
        val trust = didReceiveChallenge.protectionSpace.serverTrust
        if (trust != null && isTrusted(trust)) {
            completionHandler(NSURLSessionAuthChallengeUseCredential, NSURLCredential.credentialForTrust(trust))
        } else {
            completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, null)
        }
    }

    private fun isTrusted(trust: SecTrustRef): Boolean = SecTrustEvaluateWithError(trust, null)
}

fun DarwinClientEngineConfig.checked() {
    handleChallenge { _, _, challenge, completionHandler ->
        val trust = challenge.protectionSpace.serverTrust
        val ok = trust != null && SecTrustEvaluateWithError(trust, null)
        completionHandler(
            if (ok) NSURLSessionAuthChallengeUseCredential else NSURLSessionAuthChallengeCancelAuthenticationChallenge,
            if (ok) NSURLCredential.create(trust = trust!!) else null,
        )
    }
}
