package com.acme.app;

import android.hardware.biometrics.BiometricPrompt;

class Legacy {
    void go(BiometricPrompt prompt, CancellationSignal signal, Executor executor, BiometricPrompt.AuthenticationCallback cb) {
        prompt.authenticate(signal, executor, cb);
    }
}
