package com.demo
fun hooked() = File("/proc/self/maps").readText().contains("frida")
