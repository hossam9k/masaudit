package com.acme.app;

class RouterJava extends Activity {
    void route() {
        Intent forward = (Intent) getIntent().getParcelableExtra("forward");
        startActivity(forward);
    }
}
