package com.demo
fun keyManagers(ctx: Context): Array<KeyManager> {
    val ks = KeyStore.getInstance("PKCS12")
    ks.load(ctx.assets.open("client.p12"), "Pa55w0rd!".toCharArray())
    val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
    kmf.init(ks, "Pa55w0rd!".toCharArray())
    return kmf.keyManagers
}
