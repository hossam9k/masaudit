// A URLSession delegate that builds the credential inside a null-safe let block.
package com.bank.net

import platform.Foundation.*
import platform.darwin.NSObject

class SessionDelegate : NSObject(), NSURLSessionDelegateProtocol {
    override fun URLSession(
        session: NSURLSession,
        didReceiveChallenge: NSURLAuthenticationChallenge,
        completionHandler: (NSURLSessionAuthChallengeDisposition, NSURLCredential?) -> Unit,
    ) {
        didReceiveChallenge.protectionSpace.serverTrust?.let { trust ->
            completionHandler(NSURLSessionAuthChallengeUseCredential, NSURLCredential.credentialForTrust(trust))
        } ?: completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, null)
    }
}
