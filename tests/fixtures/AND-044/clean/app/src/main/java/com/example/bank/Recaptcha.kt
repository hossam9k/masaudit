package com.example.bank

import com.google.android.gms.safetynet.SafetyNet

fun verify(context: Context) {
    SafetyNet.getClient(context).verifyWithRecaptcha(BuildConfig.RECAPTCHA_KEY)
    SafetyNet.getClient(context).isVerifyAppsEnabled
    // SafetyNet.getClient(context).attest(nonce, key)
}
