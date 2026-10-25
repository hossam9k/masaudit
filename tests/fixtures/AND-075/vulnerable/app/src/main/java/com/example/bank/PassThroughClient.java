package com.example.bank;

import android.webkit.WebView;
import android.webkit.WebViewClient;

public class PassThroughClient extends WebViewClient {
    @Override
    public boolean shouldOverrideUrlLoading(WebView view, String url) {
        view.loadUrl(url);
        return true;
    }
}
