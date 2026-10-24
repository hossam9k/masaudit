package com.example.bank

const val ACTION_ADD_WIDGET = "actionWidgetAdded"

class WidgetAddedReceiver(private val context: Context) : BroadcastReceiver() {
    fun start() {
        context.registerExportedReceiver(this, IntentFilter(ACTION_ADD_WIDGET))       // reported here
    }
}

class NewAppReceiver(private val context: Context) : BroadcastReceiver() {
    fun start() {
        IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addDataScheme("package")
        }.run {
            context.registerExportedReceiver(this@NewAppReceiver, this)           // system broadcast only
        }
    }
}
