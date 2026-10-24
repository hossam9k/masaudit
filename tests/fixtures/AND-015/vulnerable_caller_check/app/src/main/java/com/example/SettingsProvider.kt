package com.example

import android.content.ContentProvider
import android.net.Uri
import android.os.ParcelFileDescriptor

class SettingsProvider : ContentProvider() {
    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor? {
        if (!isTrustedCaller()) return null
        return null
    }

    private fun isTrustedCaller(): Boolean {
        val caller = callingPackage ?: return false
        return caller in TRUSTED
    }

    companion object {
        val TRUSTED = setOf("com.example.migrator")
    }
}
