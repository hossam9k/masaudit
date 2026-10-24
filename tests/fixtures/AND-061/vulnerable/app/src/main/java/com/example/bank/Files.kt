package com.example.bank

fun share(context: Context, file: File) {
    context.openFileOutput("export.json", Context.MODE_WORLD_READABLE).use { }
    file.setReadable(true, false)
}
