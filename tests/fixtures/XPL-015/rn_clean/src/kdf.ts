import CryptoJS from 'crypto-js';
import { pbkdf2Sync } from 'react-native-quick-crypto';

export function deriveKey(password: string, salt: CryptoJS.lib.WordArray) {
  return CryptoJS.PBKDF2(password, salt, { keySize: 256 / 32, iterations: 600000, hasher: CryptoJS.algo.SHA256 });
}

export function deriveNative(password: string, salt: Buffer) {
  return pbkdf2Sync(password, salt, 600_000, 32, 'sha256');
}
