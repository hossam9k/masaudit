package com.example.bank

class DeepLinkActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val typed = intent.getSerializableExtra("payload", Transfer::class.java)
        val saved = savedInstanceState?.getSerializable("state")
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        val picked = data?.getSerializableExtra("picked")
    }
}
