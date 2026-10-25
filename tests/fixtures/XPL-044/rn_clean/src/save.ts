import RNFS from 'react-native-fs';
import * as FileSystem from 'expo-file-system';

export async function save(notes: string, token: string) {
  await RNFS.writeFile(RNFS.DocumentDirectoryPath + '/notes.txt', notes, 'utf8');
  await FileSystem.writeAsStringAsync(FileSystem.documentDirectory + 'session.bin', encrypt(token));
}

declare function encrypt(v: string): string;
