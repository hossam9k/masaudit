import Clipboard from '@react-native-clipboard/clipboard';
import * as ExpoClipboard from 'expo-clipboard';
import AsyncStorage from '@react-native-async-storage/async-storage';

export async function copyToken() {
  const t = await AsyncStorage.getItem('@auth_token');
  Clipboard.setString(t || '');
}

export function copyPassword(password: string) {
  return ExpoClipboard.setStringAsync(password);
}

export function copySeed(wallet: { mnemonic: string }) {
  Clipboard.setString(wallet.mnemonic);
}
