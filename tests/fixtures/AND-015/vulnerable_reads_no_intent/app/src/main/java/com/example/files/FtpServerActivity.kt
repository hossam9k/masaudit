package com.example.files

class FtpServerActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState == null) {
            supportFragmentManager.commit { add(android.R.id.content, FtpServerFragment()) }
        }
    }
}
