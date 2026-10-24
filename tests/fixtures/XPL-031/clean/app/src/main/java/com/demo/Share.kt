package com.demo
@Entity(tableName = "shares")
data class ShareEntity(
    @PrimaryKey val id: Long,
    val token: String?,
    val path: String,
)
