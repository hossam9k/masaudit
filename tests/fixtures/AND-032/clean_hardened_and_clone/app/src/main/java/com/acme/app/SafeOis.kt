package com.acme.app

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import java.io.ObjectStreamClass
import java.io.Serializable

private val ALLOW = setOf("java.lang.String", "java.util.HashMap")

// The OWASP mitigation itself: a class allowlist in resolveClass.
class SafeOis(s: InputStream) : ObjectInputStream(s) {
    override fun resolveClass(d: ObjectStreamClass): Class<*> =
        if (d.name in ALLOW) super.resolveClass(d) else throw ClassNotFoundException(d.name)
}

fun readSettings(input: InputStream): Any? = SafeOis(input).use { it.readObject() }

// An in-memory deep copy: the bytes come from the app's own object a line earlier.
@Suppress("UNCHECKED_CAST")
fun <T : Serializable> clone(t: T): T {
    val bos = ByteArrayOutputStream()
    ObjectOutputStream(bos).use { it.writeObject(t) }
    return ObjectInputStream(ByteArrayInputStream(bos.toByteArray())).readObject() as T
}
