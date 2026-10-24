package com.demo
private val SALT = "com.demo.salt".toByteArray()
fun derive(password: CharArray) = PBEKeySpec(password, SALT, 600_000, 256)
fun inline(password: CharArray) = PBEKeySpec(password, "static-salt".toByteArray(), 600_000, 256)
