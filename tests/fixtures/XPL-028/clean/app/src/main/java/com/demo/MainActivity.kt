package com.demo
class MainActivity : AppCompatActivity()
fun locked(km: KeyguardManager) = km.isDeviceSecure
