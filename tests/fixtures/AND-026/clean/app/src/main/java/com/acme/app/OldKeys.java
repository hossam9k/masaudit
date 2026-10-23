package com.acme.app;

class OldKeys {
    KeyGenParameterSpec spec() {
        return new KeyGenParameterSpec.Builder("k", KeyProperties.PURPOSE_DECRYPT)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationValidityDurationSeconds(-1)
            .build();
    }
}
