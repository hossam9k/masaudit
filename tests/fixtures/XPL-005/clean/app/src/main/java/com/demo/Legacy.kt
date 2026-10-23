package com.demo
val c = Cipher.getInstance("AES/GCM/NoPadding")
val modes = arrayOf(KeyProperties.BLOCK_MODE_GCM)
// was "AES/CBC/PKCS5Padding" before 3.0
