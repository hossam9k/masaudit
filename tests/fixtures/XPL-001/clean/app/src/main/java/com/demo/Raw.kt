package com.demo
fun rawPrivateKey(pem: String) = pem.replace("-----BEGIN PRIVATE KEY-----", "").replace("\n", "")
