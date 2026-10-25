import CryptoJS from 'crypto-js';

const SALT = 'notes-app-salt';

export function deriveKey(password: string) {
  return CryptoJS.PBKDF2(password, SALT, { keySize: 8, iterations: 600000, hasher: CryptoJS.algo.SHA256 });
}
