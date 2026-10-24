package com.demo
fun emulator() = Build.FINGERPRINT.startsWith("generic") || Build.HARDWARE.contains("goldfish")
