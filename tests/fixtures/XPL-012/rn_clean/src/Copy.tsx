import Clipboard from '@react-native-clipboard/clipboard';
import { setStringAsync } from 'expo-clipboard';

export function copyLink(url: string) {
  Clipboard.setString(url);
}

export async function copyAddress(wallet: { address: string }) {
  await setStringAsync(wallet.address);
}

// A settings store with the same method name is not the clipboard.
const prefs = { setString: (k: string, v: string) => [k, v] };
prefs.setString('token', 'value');
