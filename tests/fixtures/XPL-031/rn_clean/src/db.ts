import Realm from 'realm';
import SQLite from 'react-native-sqlite-storage';

export const UserSchema = {
  name: 'User',
  properties: { id: 'string', email: 'string', password: 'string' },
};

export function openRealm(key: ArrayBuffer) {
  return new Realm({ schema: [UserSchema], encryptionKey: key });
}

export async function open() {
  const db = await SQLite.openDatabase({ name: 'app.db', location: 'default' });
  await db.executeSql('CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, body TEXT)');
  return db;
}
