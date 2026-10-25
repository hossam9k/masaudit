package com.wallet

import com.facebook.react.bridge.*
import java.io.File

class ConfigModule(c: ReactApplicationContext) : ReactContextBaseJavaModule(c) {
  override fun getName() = "Config"

  // Runtime.getRuntime().exec(cmd) in a comment does not count.
  @ReactMethod fun readConfig(name: String, p: Promise) {
    val base = File(reactApplicationContext.filesDir, "config").canonicalFile
    val file = File(base, "$name.json").canonicalFile
    if (!file.path.startsWith(base.path + File.separator)) { p.reject("E", "bad path"); return }
    p.resolve(file.readText())
  }

  @ReactMethod fun cacheSize(p: Promise) {
    p.resolve(File(reactApplicationContext.cacheDir, "img").length().toDouble())
  }

  @ReactMethod fun uptime(p: Promise) {
    p.resolve(Runtime.getRuntime().exec(arrayOf("uptime")).inputStream.bufferedReader().readText())
  }

  fun notExposed(path: String) = File(path).readText()
}
