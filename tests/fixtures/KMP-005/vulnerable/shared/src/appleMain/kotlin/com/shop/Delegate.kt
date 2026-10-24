package com.shop

import platform.Foundation.*

class Delegate : NSObject(), NSURLSessionDelegateProtocol {
    override fun URLSession(
        session: NSURLSession,
        didReceiveChallenge: NSURLAuthenticationChallenge,
        completionHandler: (NSURLSessionAuthChallengeDisposition, NSURLCredential?) -> Unit,
    ) {
        val cred = NSURLCredential.credentialForTrust(didReceiveChallenge.protectionSpace.serverTrust)
        completionHandler(NSURLSessionAuthChallengeUseCredential, cred)
    }
}
