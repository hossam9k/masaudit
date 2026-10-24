package com.demo
private const val LOGCAT = "logcat -d"
fun su() = Runtime.getRuntime().exec(arrayOf("which", "su"))
fun logs() = Runtime.getRuntime().exec(LOGCAT)
fun id() = ProcessBuilder("id").start()
fun plain() = Runtime.getRuntime().exec("getprop ro.build.tags")
