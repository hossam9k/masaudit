package com.acme.app

class DeepLinkActivity : AppCompatActivity() {
    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        val fwd = intent.getParcelableExtra<Intent>("forward")
        startActivity(fwd)
    }
}
