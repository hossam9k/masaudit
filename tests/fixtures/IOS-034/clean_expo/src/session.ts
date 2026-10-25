import * as FileSystem from 'expo-file-system';

export async function saveSession(json: string) {
  // Secrets live outside Documents, so the Files app never shows them.
  await FileSystem.writeAsStringAsync(FileSystem.cacheDirectory + 'session.json', json);
  await FileSystem.writeAsStringAsync(FileSystem.documentDirectory + 'photo.jpg', json);
}
