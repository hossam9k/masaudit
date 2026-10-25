package com.example.bank;

import android.app.Activity;
import android.webkit.WebView;
import android.widget.EditText;

public class UrlActivity extends Activity {
    void open(WebView webView, EditText uriText) {
        webView.getSettings().setJavaScriptEnabled(true);
        webView.loadUrl(uriText.getText().toString());
    }
}
