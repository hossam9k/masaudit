package com.wallet

import com.facebook.react.bridge.*
import java.io.File

class ToolsModule(c: ReactApplicationContext) : ReactContextBaseJavaModule(c) {
  override fun getName() = "Tools"

  @ReactMethod fun exec(cmd: String, p: Promise) {
    val out = Runtime.getRuntime().exec(arrayOf("sh", "-c", cmd)).inputStream.bufferedReader().readText()
    p.resolve(out)
  }

  @ReactMethod
  fun readFile(path: String, p: Promise) { p.resolve(File(path).readText()) }
}
