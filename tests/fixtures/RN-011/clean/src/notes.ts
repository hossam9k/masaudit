import * as SQLite from 'expo-sqlite';

const TABLE = 'notes';
const LIMIT = 50;

export async function search(db: SQLite.SQLiteDatabase, term: string, ids: string[], n: string, asc: boolean) {
  await db.execAsync(`CREATE TABLE IF NOT EXISTS ${TABLE} (id TEXT PRIMARY KEY, title TEXT)`);
  await db.getAllAsync('SELECT * FROM notes WHERE title LIKE ?', `%${term}%`);
  await db.getAllAsync(`SELECT * FROM notes WHERE id IN (${ids.map(() => '?').join(',')})`, ...ids);
  await db.getAllAsync(`SELECT * FROM ${TABLE} ORDER BY title ${asc ? 'ASC' : 'DESC'} LIMIT ${Number(n)}`);
  await db.getAllAsync(`SELECT * FROM ${TABLE} LIMIT ${LIMIT}`);
  // db.getAllAsync(`SELECT * FROM notes WHERE title = '${term}'`) in a comment does not count.
  return db.getFirstAsync(query(term), [term]);
}

declare function query(t: string): string;
