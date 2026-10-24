package com.demo
fun keyManagers(ctx: Context, password: CharArray): Array<KeyManager> {
    val ks = KeyStore.getInstance("PKCS12")
    ks.load(ctx.assets.open("client.p12"), password)
    val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
    kmf.init(ks, password)
    return kmf.keyManagers
}
