package com.example.bank

import android.provider.Settings.Secure.ANDROID_ID

// Settings.Secure.ANDROID_ID would track the device
class Device(private val account: Account) {
    val label = "android_id"
    fun id(): String = account.deviceId
    fun linked(store: SignalStore): Int = store.account().getDeviceId()
    fun telephonyName(): String = "TelephonyManager"
    fun address(adapter: Adapter): String = adapter.address
}
