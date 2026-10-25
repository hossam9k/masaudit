package com.demo;

public class DoLogin {
    String showUsernamePreference = "always";

    boolean empty(String password) {
        return password.equals("");
    }

    boolean field(String inputType, String fieldName) {
        return inputType.equals("password") || fieldName.equals("username");
    }

    boolean showName() {
        return showUsernamePreference.equals("always");
    }

    boolean sameAsConfirm(String password, String confirm) {
        return password.equals(confirm);
    }
}
