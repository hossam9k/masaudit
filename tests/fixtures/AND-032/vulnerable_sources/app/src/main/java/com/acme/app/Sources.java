package com.acme.app;

import android.os.ParcelFileDescriptor;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;

class Sources {
    // High: the stream belongs to the binder caller (nextcloud's InputStreamBinder pattern).
    public ParcelFileDescriptor performRequest(ParcelFileDescriptor in) throws Exception {
        InputStream is = new ParcelFileDescriptor.AutoCloseInputStream(in);
        Object o = new ObjectInputStream(is).readObject();
        return null;
    }

    // Medium: an app file, read back.
    static Object readFromFile(File file) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(file))) {
            return ois.readObject();
        }
    }

    static Object restore(File file) throws Exception {
        try (FileInputStream fileInputStream = new FileInputStream(file);
             ObjectInputStream inputStream = new ObjectInputStream(fileInputStream)) {
            return inputStream.readObject();
        }
    }

    void use(File f, ParcelFileDescriptor p) throws Exception {
        readFromFile(f);
        restore(f);
        performRequest(p);
    }
}
