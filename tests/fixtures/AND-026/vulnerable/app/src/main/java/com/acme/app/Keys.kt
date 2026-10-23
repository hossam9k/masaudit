package com.acme.app

fun spec(): KeyGenParameterSpec =
    KeyGenParameterSpec.Builder("k", KeyProperties.PURPOSE_SIGN)
        .setUserAuthenticationRequired(true)
        .setInvalidatedByBiometricEnrollment(false)
        .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
        .build()
