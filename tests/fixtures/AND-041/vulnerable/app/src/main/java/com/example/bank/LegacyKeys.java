package com.example.bank;

class LegacyKeys {
    KeyGenParameterSpec spec() {
        return new KeyGenParameterSpec.Builder("old", KeyProperties.PURPOSE_ENCRYPT)
            .setRandomizedEncryptionRequired(false).build();
    }
}
