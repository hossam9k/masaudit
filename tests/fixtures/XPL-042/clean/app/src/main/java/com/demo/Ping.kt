package com.demo
private const val FILTER_SPEC = "*:I"
private val logcatCommand = arrayOf("logcat", "-d", "-v", "threadtime")
fun ping(serverIP: String) = Runtime.getRuntime().exec(arrayOf("ping", "-c", "1", serverIP))
fun logs() = Runtime.getRuntime().exec("logcat -d " + FILTER_SPEC)
fun logs2() = Runtime.getRuntime().exec(logcatCommand)
class ProcessExecutor { fun execute(command: String) = Runtime.getRuntime().exec(command) }
fun open(command: List<String>) = ProcessBuilder(command).start()
// No shell: the string is split on spaces and `ping` runs with them as its arguments, as with the array above.
fun pingText(host: String) = Runtime.getRuntime().exec("ping -c 1 " + host)
fun open(file: java.io.File) = Runtime.getRuntime().exec("xdg-open ${file.absolutePath}")
