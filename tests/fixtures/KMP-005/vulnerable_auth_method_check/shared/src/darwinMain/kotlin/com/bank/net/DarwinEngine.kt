// Checking only the authentication method is not trust evaluation: any server certificate is accepted.
package com.bank.net

import io.ktor.client.engine.darwin.DarwinClientEngineConfig
import platform.Foundation.*

fun DarwinClientEngineConfig.acceptServerTrust() {
    handleChallenge { _, _, challenge, completionHandler ->
        if (challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust) {
            completionHandler(
                NSURLSessionAuthChallengeUseCredential,
                NSURLCredential
                    .create(trust = challenge.protectionSpace.serverTrust!!),
            )
        } else {
            completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, null)
        }
    }
}
