package com.acme.app;

// Vendored helper: nothing in the project calls decodeToObject.
public class Base64Tools {
    public static Object decodeToObject(String encodedObject)
    throws java.io.IOException, ClassNotFoundException {
        return decodeToObject(encodedObject, 0, null);
    }

    public static Object decodeToObject(
    String encodedObject, int options, final ClassLoader loader)
    throws java.io.IOException, ClassNotFoundException {
        byte[] objBytes = decode(encodedObject, options);
        java.io.ByteArrayInputStream bais = new java.io.ByteArrayInputStream(objBytes);
        java.io.ObjectInputStream ois;
        if (loader == null) {
            ois = new java.io.ObjectInputStream(bais);
        } else {
            ois = new java.io.ObjectInputStream(bais) {
                @Override
                public Class<?> resolveClass(java.io.ObjectStreamClass streamClass)
                throws java.io.IOException, ClassNotFoundException {
                    return Class.forName(streamClass.getName(), false, loader);
                }
            };
        }
        return ois.readObject();
    }

    static byte[] decode(String s, int options) {
        return new byte[0];
    }
}
