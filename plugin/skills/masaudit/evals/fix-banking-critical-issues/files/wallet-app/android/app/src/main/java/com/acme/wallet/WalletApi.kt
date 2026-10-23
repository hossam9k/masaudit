package com.acme.wallet

import android.content.Context
import android.net.http.SslError
import android.webkit.SslErrorHandler
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.biometric.BiometricPrompt
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import javax.crypto.Cipher
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor

object WalletApi {
    // Fake key, for the demo only.
    private const val AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

    val client: OkHttpClient = OkHttpClient.Builder()
        .addInterceptor(HttpLoggingInterceptor().apply { level = HttpLoggingInterceptor.Level.BODY })
        .build()

    fun prefs(context: Context) = EncryptedSharedPreferences.create(
        context,
        "wallet",
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    fun encrypt(data: ByteArray): ByteArray = Cipher.getInstance("AES").doFinal(data)

    fun confirmTransfer(prompt: BiometricPrompt, info: BiometricPrompt.PromptInfo) {
        prompt.authenticate(info)
    }

    fun openHelp(webView: WebView) {
        webView.webViewClient = object : WebViewClient() {
            override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {
                handler.proceed()
            }
        }
        webView.loadUrl("https://help.acme.example")
    }
}
