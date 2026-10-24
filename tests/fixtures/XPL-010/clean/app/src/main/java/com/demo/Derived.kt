package com.demo
fun check(it: Server, recoveryPassword: String?, token: Optional<String>, restoreMethodToken: String) {
    Timber.d("Password: ${it.supportsPasswordLogin()}")
    Log.i(TAG, "recoveryPassword: ${recoveryPassword != null}")
    Log.i(TAG, "Token changed. newLength: " + token.get().length())
    Log.d(TAG, "restore ***${restoreMethodToken.takeLast(4)}")
    Log.w(TAG, clearTokenError)
    Log.e(TAG, getString(R.string.error_retrieving_oauth_token), e)
    Log.i(TAG, "has pin? " + !TextUtils.isEmpty(registrationPassword))
    Log.w(TAG, "non-MOB token (tokenId: " + amount.getTokenId() + ")")
}
