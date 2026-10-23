package com.demo
val sha = MessageDigest.getInstance("SHA-256")
val label = "MD5 is broken"
// MessageDigest.getInstance("MD5")
val mac = Mac.getInstance("HmacSHA256")
