package com.acme.app;

class LinkJava extends Activity {
    void open() {
        String url = getIntent().getStringExtra("url");
        webView.loadUrl(url);
    }
}
