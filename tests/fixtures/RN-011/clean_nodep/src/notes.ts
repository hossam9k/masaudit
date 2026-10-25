import * as SQLite from 'expo-sqlite';

export async function search(db: SQLite.SQLiteDatabase, term: string) {
  return db.getAllAsync(`SELECT * FROM notes WHERE title LIKE '%${term}%'`);
}

export async function remove(db: SQLite.SQLiteDatabase, id: string) {
  const sql = 'DELETE FROM notes WHERE id = ' + id;
  await db.runAsync(sql);
}
