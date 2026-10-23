package com.acme.app

fun read(input: InputStream): Any? =
    ObjectInputStream(input).use { it.readObject() }
