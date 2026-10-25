package com.bank.app

import com.facebook.react.ReactActivity
import com.facebook.react.modules.network.OkHttpClientFactory
import com.facebook.react.modules.network.OkHttpClientProvider
import okhttp3.OkHttpClient

// The factory is in the repository and sets no CertificatePinner, so nothing pins.
class TimeoutClientFactory : OkHttpClientFactory {
    override fun createNewNetworkModuleClient(): OkHttpClient =
        OkHttpClientProvider.createClientBuilder().build()
}

class MainActivity : ReactActivity() {
    override fun onCreate(savedInstanceState: android.os.Bundle?) {
        OkHttpClientProvider.setOkHttpClientFactory(TimeoutClientFactory())
        super.onCreate(savedInstanceState)
    }
}
