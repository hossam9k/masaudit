package com.example.vpn;

// The library comes out of the app's own signed APK (sourceDir), not from storage another app can write.
public final class LibraryLoader {
    public static void load(final android.content.Context context, final String libName) throws Exception {
        try {
            System.loadLibrary(libName);
            return;
        } catch (final UnsatisfiedLinkError e) {
            java.io.File f = java.io.File.createTempFile("lib", ".so", context.getCodeCacheDir());
            extractFrom(context.getApplicationInfo().sourceDir, libName, f);
            System.load(f.getAbsolutePath());
        }
    }

    private static void extractFrom(String apk, String libName, java.io.File out) { }
}
