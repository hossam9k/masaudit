package com.bank.app

import com.facebook.react.ReactActivity
import com.facebook.react.modules.network.OkHttpClientProvider
import com.bank.app.internals.CustomNetworkModule   // added by a private build step, not in this repository

class MainActivity : ReactActivity() {
    override fun onCreate(savedInstanceState: android.os.Bundle?) {
        OkHttpClientProvider.setOkHttpClientFactory(CustomNetworkModule())
        super.onCreate(savedInstanceState)
    }
}
