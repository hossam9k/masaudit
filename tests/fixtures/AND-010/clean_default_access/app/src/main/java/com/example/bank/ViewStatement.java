package com.example.bank;

import android.app.Activity;
import android.os.Environment;
import android.webkit.WebView;
import android.widget.EditText;

public class ViewStatement extends Activity {
    void show(WebView webView, String user) {
        webView.getSettings().setJavaScriptEnabled(true);
        webView.getSettings().setAllowFileAccess(false);
        webView.loadUrl("file://" + Environment.getExternalStorageDirectory() + "/Statements_" + user + ".html");
    }

    void plain(WebView webView, EditText uriText) {
        webView.loadUrl(uriText.getText().toString());
    }
}
