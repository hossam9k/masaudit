package com.acme.app

import dalvik.system.DexClassLoader

fun load() {
    System.loadLibrary("native-lib")
    // DexClassLoader(path, optDir, null, parent) was removed
}
