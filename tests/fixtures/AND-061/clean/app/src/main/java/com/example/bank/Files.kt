package com.example.bank

// Context.MODE_WORLD_READABLE was removed for good reason
fun share(context: Context, file: File) {
    context.openFileOutput("export.json", Context.MODE_PRIVATE).use { }
    file.setReadable(true, true)
    file.setReadable(true)
}
