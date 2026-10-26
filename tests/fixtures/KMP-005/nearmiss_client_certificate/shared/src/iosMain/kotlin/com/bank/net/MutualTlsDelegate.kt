// mTLS: UseCredential answers the client-certificate challenge; server trust falls back to default handling.
package com.bank.net

import platform.Foundation.*
import platform.Security.SecIdentityRef
import platform.darwin.NSObject

class MutualTlsDelegate(private val identity: SecIdentityRef) : NSObject(), NSURLSessionDelegateProtocol {
    override fun URLSession(
        session: NSURLSession,
        didReceiveChallenge: NSURLAuthenticationChallenge,
        completionHandler: (NSURLSessionAuthChallengeDisposition, NSURLCredential?) -> Unit,
    ) {
        when (didReceiveChallenge.protectionSpace.authenticationMethod) {
            NSURLAuthenticationMethodClientCertificate -> completionHandler(
                NSURLSessionAuthChallengeUseCredential,
                NSURLCredential.create(
                    identity = identity,
                    certificates = null,
                    persistence = NSURLCredentialPersistence.NSURLCredentialPersistenceForSession,
                ),
            )
            // Not NSURLCredential.credentialForTrust: the system evaluates server trust.
            else -> completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, null)
        }
    }
}
