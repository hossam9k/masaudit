import RNFS from 'react-native-fs';
import * as FileSystem from 'expo-file-system';

export async function save(token: string, password: string) {
  await RNFS.writeFile(RNFS.DocumentDirectoryPath + '/session.txt', token, 'utf8');
  await FileSystem.writeAsStringAsync(FileSystem.documentDirectory + 'creds.json', JSON.stringify({ password }));
}
