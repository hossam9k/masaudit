package com.acme.app;

public abstract class PassphraseActivity extends Activity {
    void done() {
        Intent next = getIntent().getParcelableExtra("next_intent");
        if (next != null) startActivity(next);
    }
}
