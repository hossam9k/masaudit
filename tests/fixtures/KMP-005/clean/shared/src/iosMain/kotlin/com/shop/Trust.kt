package com.shop

import io.ktor.client.engine.darwin.*
import platform.Foundation.*
import platform.Security.*

fun DarwinClientEngineConfig.checkedTrust() {
    handleChallenge { _, _, challenge, completionHandler ->
        val trust = challenge.protectionSpace.serverTrust
        if (trust != null && SecTrustEvaluateWithError(trust, null)) {
            completionHandler(NSURLSessionAuthChallengeUseCredential, NSURLCredential.create(trust = trust))
        } else {
            completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, null)
        }
    }
}
