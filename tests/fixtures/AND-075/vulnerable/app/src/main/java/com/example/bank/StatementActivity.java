package com.example.bank;

import android.app.Activity;
import android.webkit.WebView;

public class StatementActivity extends Activity {
    void show(WebView webView) {
        webView.getSettings().setJavaScriptEnabled(true);
        webView.setWebViewClient(new PassThroughClient());
        webView.loadUrl("https://statements.example.com/");
    }
}
