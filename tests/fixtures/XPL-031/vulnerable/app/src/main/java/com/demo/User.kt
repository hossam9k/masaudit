package com.demo
@Entity(tableName = "accounts")
data class Account(
    @PrimaryKey val id: Long,
    val email: String,
    val refreshToken: String,
    val password: String,
)
