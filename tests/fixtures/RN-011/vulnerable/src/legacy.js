import SQLite from 'react-native-sqlite-storage';

export function byUser(db, name) {
  db.transaction((tx) => {
    tx.executeSql("SELECT * FROM users WHERE name = '" + name + "'", [], (t, r) => r);
  });
}
