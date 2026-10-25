import Realm from 'realm';
import SQLite from 'react-native-sqlite-storage';

export const UserSchema = {
  name: 'User',
  properties: { id: 'string', email: 'string', password: 'string' },
};

export const realm = new Realm({ schema: [UserSchema] });

export async function open() {
  const db = await SQLite.openDatabase({ name: 'app.db', location: 'default' });
  await db.executeSql('CREATE TABLE IF NOT EXISTS session (id INTEGER PRIMARY KEY, access_token TEXT)');
  return db;
}
