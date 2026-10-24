package com.acme.app

enum class AppStage { NEW, ESTABLISHED }

class UserStage(val key: Int = 1, val appStage: AppStage)

// One-shot migrations over values the app owns: an enum, the user's own account ID, a config default.
val MIGRATION_3_4 = object : Migration(3, 4) {
    override fun migrate(db: SupportSQLiteDatabase) {
        val stage = AppStage.NEW
        val aci = getLocalAci()?.toString()
        db.execSQL("INSERT INTO user_stage VALUES (1, \"$stage\")")
        db.execSQL("UPDATE prekeys SET account_id = '$aci'")
    }
}

val MIGRATION_4_5 = object : Migration(4, 5) {
    override fun migrate(db: SupportSQLiteDatabase) {
        val userStage = UserStage(appStage = AppStage.ESTABLISHED)
        val defaultLang = AppConfig.instance.language
        db.execSQL("INSERT INTO user_stage VALUES (${userStage.key}, \"${userStage.appStage}\")")
        db.execSQL("INSERT INTO history SELECT COALESCE(lang, '$defaultLang') FROM old_history")
    }
}
