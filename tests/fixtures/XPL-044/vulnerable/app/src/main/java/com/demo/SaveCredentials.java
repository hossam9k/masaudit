package com.demo;

import android.content.Context;
import android.widget.EditText;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;

public class SaveCredentials {
    public void save(Context context, EditText usr, EditText pwd) throws Exception {
        File uinfo = File.createTempFile("uinfo", "tmp", context.getFilesDir());
        FileWriter fw = new FileWriter(uinfo);
        fw.write(usr.getText().toString() + ":" + pwd.getText().toString() + "\n");
        fw.close();
    }

    public void writeSecretFile(Context context) throws Exception {
        File fileName = new File(context.getFilesDir(), "secret.txt");
        String fileContent = "value";
        try (FileOutputStream output = new FileOutputStream(fileName)) {
            output.write(fileContent.getBytes());
        }
    }
}
