package com.demo;
class Unzip {
    void unzip(ZipFile zip, File dest) throws IOException {
        Enumeration<? extends ZipEntry> entries = zip.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            String name = entry.getName();
            File out = new File(dest, name);
            copy(zip.getInputStream(entry), out);
        }
    }
}
