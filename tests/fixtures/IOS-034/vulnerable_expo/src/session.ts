import * as FileSystem from 'expo-file-system';

export async function saveSession(json: string) {
  await FileSystem.writeAsStringAsync(FileSystem.documentDirectory + 'session.json', json);
  await FileSystem.writeAsStringAsync(`${FileSystem.documentDirectory}exports/statement.pdf`, json);
}
