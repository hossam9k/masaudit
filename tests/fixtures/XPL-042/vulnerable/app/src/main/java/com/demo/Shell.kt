package com.demo
fun ping(host: String) = Runtime.getRuntime().exec("ping -c 1 " + host)
fun run(cmd: String) = ProcessBuilder("sh", "-c", cmd).start()
