package com.demo
class MainActivity : AppCompatActivity()
fun emulator() = Build.FINGERPRINT.startsWith("generic") || Build.HARDWARE.contains("goldfish")
