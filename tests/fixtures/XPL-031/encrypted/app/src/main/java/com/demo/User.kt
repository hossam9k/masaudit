package com.demo
@Entity(tableName = "accounts")
data class Account(@PrimaryKey val id: Long, val refreshToken: String)
fun db(ctx: Context, pass: ByteArray) = Room.databaseBuilder(ctx, AppDb::class.java, "app.db")
    .openHelperFactory(SupportOpenHelperFactory(pass)).build()
