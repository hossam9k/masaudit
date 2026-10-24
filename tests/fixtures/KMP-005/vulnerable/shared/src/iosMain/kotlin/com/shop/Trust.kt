package com.shop

import io.ktor.client.engine.darwin.*
import platform.Foundation.*

fun DarwinClientEngineConfig.trustAll() {
    handleChallenge { _, _, challenge, completionHandler ->
        val trust = challenge.protectionSpace.serverTrust
        completionHandler(NSURLSessionAuthChallengeUseCredential, NSURLCredential.create(trust = trust))
    }
}
