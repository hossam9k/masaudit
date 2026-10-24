package com.demo
fun unzip(input: InputStream, dest: File) {
    ZipInputStream(input).use { zis ->
        var entry = zis.nextEntry
        while (entry != null) {
            val out = File(dest, entry.name)
            out.outputStream().use { zis.copyTo(it) }
            entry = zis.nextEntry
        }
    }
}
