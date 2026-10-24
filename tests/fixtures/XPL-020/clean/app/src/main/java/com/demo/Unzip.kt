package com.demo
fun unzip(input: InputStream, dest: File) {
    ZipInputStream(input).use { zis ->
        var entry = zis.nextEntry
        while (entry != null) {
            val out = File(dest, entry.name).canonicalFile
            require(out.path.startsWith(dest.canonicalPath + File.separator))
            out.outputStream().use { zis.copyTo(it) }
            entry = zis.nextEntry
        }
    }
}
fun list(input: InputStream): List<String> {
    val names = mutableListOf<String>()
    ZipInputStream(input).use { zis -> var e = zis.nextEntry; while (e != null) { names += e.name; e = zis.nextEntry } }
    return names
}
