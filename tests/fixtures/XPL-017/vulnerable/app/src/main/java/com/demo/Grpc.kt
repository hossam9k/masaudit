package com.demo
import io.grpc.ManagedChannelBuilder
val channel = ManagedChannelBuilder.forAddress("api.demo-bank.com", 443).usePlaintext().build()
