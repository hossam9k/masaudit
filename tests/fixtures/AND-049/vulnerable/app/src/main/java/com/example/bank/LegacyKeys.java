package com.example.bank;

class LegacyKeys {
    KeyGenParameterSpec spec() {
        return new KeyGenParameterSpec.Builder("k3", KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_VERIFY).build();
    }
}
