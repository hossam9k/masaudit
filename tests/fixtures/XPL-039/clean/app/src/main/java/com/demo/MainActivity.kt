package com.demo
class MainActivity : AppCompatActivity()
fun hooked() = File("/proc/self/maps").readText().contains("frida")
