import CryptoJS from 'crypto-js';
import { MMKV } from 'react-native-mmkv';
import * as Keychain from 'react-native-keychain';

export async function open() {
  const creds = await Keychain.getGenericPassword({ service: 'mmkv' });
  return new MMKV({ id: 'secure', encryptionKey: creds ? creds.password : undefined });
}

export function seal(text: string, key: CryptoJS.lib.WordArray) {
  return CryptoJS.AES.encrypt(text, key, { iv: CryptoJS.lib.WordArray.random(16) }).toString();
}

export const settings = { encryptionKey: 'not-an-mmkv-option' };
