package com.acme.app;

import android.hardware.biometrics.BiometricPrompt;

class Legacy {
    void go(BiometricPrompt prompt, BiometricPrompt.CryptoObject crypto, CancellationSignal signal, Executor executor, BiometricPrompt.AuthenticationCallback cb) {
        prompt.authenticate(crypto, signal, executor, cb);
    }
}
