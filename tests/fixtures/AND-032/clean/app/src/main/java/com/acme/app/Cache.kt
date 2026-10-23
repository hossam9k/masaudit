package com.acme.app

import java.io.ObjectInputStream

fun write(out: OutputStream, value: Serializable) = ObjectOutputStream(out).use { it.writeObject(value) }
fun read(text: String): Order = Json.decodeFromString(text)
// ObjectInputStream(input) replaced by kotlinx.serialization
