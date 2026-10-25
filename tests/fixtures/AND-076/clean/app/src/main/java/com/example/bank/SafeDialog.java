package com.example.bank;

import android.content.Context;
import android.text.InputType;
import android.view.inputmethod.EditorInfo;
import android.widget.EditText;

public class SafeDialog {
    void fields(Context context) {
        EditText password = new EditText(context);
        password.setHint("Password");
        password.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        EditText name = new EditText(context);
        name.setHint("Your name");
        EditText account = new EditText(context);
        account.setHint("Account number");
        account.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
    }
}
