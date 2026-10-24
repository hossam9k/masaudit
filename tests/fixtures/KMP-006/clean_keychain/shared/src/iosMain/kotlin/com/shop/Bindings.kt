package com.shop

import com.russhwolf.settings.KeychainSettings

fun provideSettings() = KeychainSettings(service = "com.shop.secrets")
