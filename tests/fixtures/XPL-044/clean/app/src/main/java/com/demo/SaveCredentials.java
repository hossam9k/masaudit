package com.demo;

import android.content.Context;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import javax.crypto.Cipher;

public class SaveCredentials {
    // The token is encrypted with a Keystore key before it is written.
    public void save(Context context, Cipher cipher, String token) throws Exception {
        byte[] sealed = cipher.doFinal(token.getBytes());
        try (FileOutputStream output = new FileOutputStream(new File(context.getFilesDir(), "token.bin"))) {
            output.write(sealed);
        }
    }

    public void saveNote(Context context, String note) throws Exception {
        FileWriter fw = new FileWriter(new File(context.getFilesDir(), "notes.txt"));
        fw.write(note);
        fw.close();
    }

    public void log(String password) {
        System.out.println("password length " + password.length());
    }
}
