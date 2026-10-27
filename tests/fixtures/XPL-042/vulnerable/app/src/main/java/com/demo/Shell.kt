package com.demo
fun ping(host: String) = Runtime.getRuntime().exec(arrayOf("sh", "-c", "ping -c 1 " + host))
fun run(cmd: String) = ProcessBuilder("sh", "-c", cmd).start()
fun root(cmd: String) = Runtime.getRuntime().exec("su -c " + cmd)
