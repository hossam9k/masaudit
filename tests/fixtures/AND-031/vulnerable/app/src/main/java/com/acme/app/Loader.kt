package com.acme.app

fun load(path: String, optDir: String, parent: ClassLoader, lib: File) {
    val loader = DexClassLoader(path, optDir, null, parent)
    System.load(lib.absolutePath)
}
