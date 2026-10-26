// prod() evaluates server trust; staging() answers with a credential for whatever trust arrives.
package com.bank.net

import io.ktor.client.engine.darwin.DarwinClientEngineConfig
import platform.Foundation.*
import platform.Security.SecTrustEvaluateWithError

fun DarwinClientEngineConfig.prod() {
    handleChallenge { _, _, challenge, completionHandler ->
        val trust = challenge.protectionSpace.serverTrust
        if (trust != null && SecTrustEvaluateWithError(trust, null)) {
            completionHandler(NSURLSessionAuthChallengeUseCredential, NSURLCredential.create(trust = trust))
        } else {
            completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, null)
        }
    }
}

fun DarwinClientEngineConfig.staging() {
    handleChallenge { _, _, challenge, completionHandler ->
        val trust = challenge.protectionSpace.serverTrust!!
        completionHandler(NSURLSessionAuthChallengeUseCredential, NSURLCredential.create(trust = trust))
    }
}
