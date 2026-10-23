package com.acme.app

class Router : Activity() {
    fun route() {
        val next = intent.getParcelableExtra<Intent>("next")
        if (next != null) startActivity(next)
        startActivity(intent.getParcelableExtra("forward"))
    }
}
