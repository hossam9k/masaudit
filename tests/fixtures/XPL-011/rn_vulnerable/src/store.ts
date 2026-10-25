import CryptoJS from 'crypto-js';
import { MMKV } from 'react-native-mmkv';

const SECRET_KEY = 'k3y-f0r-th3-n0t3s';

export const storage = new MMKV({ id: 'secure', encryptionKey: 'mmkv-static-key-1' });

export function seal(text: string) {
  return CryptoJS.AES.encrypt(text, SECRET_KEY).toString();
}

export function sealWords(text: string) {
  const aesKey = CryptoJS.enc.Utf8.parse('0123456789abcdef');
  return CryptoJS.AES.encrypt(text, aesKey, { iv: CryptoJS.lib.WordArray.random(16) }).toString();
}
