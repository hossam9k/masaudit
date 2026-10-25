import CryptoJS from 'crypto-js';

export function deriveKey(password: string) {
  const salt = CryptoJS.lib.WordArray.random(16);
  return CryptoJS.PBKDF2(password, salt, { keySize: 8, iterations: 600000, hasher: CryptoJS.algo.SHA256 });
}
