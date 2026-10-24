package com.example.bank;

class Sync {
    static final String ACTION_SYNC = "com.example.bank.action.SYNC";
    void run(Context context) {
        Intent intent = new Intent(ACTION_SYNC);
        context.startService(intent);
    }
}
