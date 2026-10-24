package com.shop

import com.russhwolf.settings.NSUserDefaultsSettings
import platform.Foundation.NSUserDefaults

fun provideSettings() = NSUserDefaultsSettings(NSUserDefaults.standardUserDefaults)
