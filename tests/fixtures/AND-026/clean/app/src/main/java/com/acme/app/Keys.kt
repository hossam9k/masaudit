package com.acme.app

fun spec(): KeyGenParameterSpec =
    KeyGenParameterSpec.Builder("k", KeyProperties.PURPOSE_SIGN)
        .setUserAuthenticationRequired(true)
        // .setInvalidatedByBiometricEnrollment(false) would keep the key after new enrollment
        .setInvalidatedByBiometricEnrollment(true)
        .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        .build()

fun pinOnly(): KeyGenParameterSpec =
    KeyGenParameterSpec.Builder("p", KeyProperties.PURPOSE_SIGN)
        .setUserAuthenticationRequired(true)
        .setUserAuthenticationParameters(0, KeyProperties.AUTH_DEVICE_CREDENTIAL)
        .build()
