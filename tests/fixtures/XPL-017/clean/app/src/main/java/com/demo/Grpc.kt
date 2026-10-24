package com.demo
import io.grpc.ManagedChannelBuilder
val channel = ManagedChannelBuilder.forAddress("api.demo-bank.com", 443).useTransportSecurity().build()
val local = ManagedChannelBuilder.forAddress("10.0.2.2", 50051).usePlaintext().build()
