import CryptoJS from 'crypto-js';

// CryptoJS.AES.encrypt(note, 'passphrase') in a comment does not count.
export function seal(note: string, rawKeyHex: string) {
  const key = CryptoJS.enc.Hex.parse(rawKeyHex);
  const iv = CryptoJS.lib.WordArray.random(16);
  return CryptoJS.AES.encrypt(note, key, { iv }).toString();
}

export function derived(note: string, password: string, salt: string) {
  const key = CryptoJS.PBKDF2(password, salt, { keySize: 8, iterations: 600000, hasher: CryptoJS.algo.SHA256 });
  return CryptoJS.AES.encrypt(note, key, { iv: CryptoJS.lib.WordArray.random(16) });
}

export function ecb(note: string, k: string) {
  // ECB with a raw key is XPL-004's finding, not a passphrase.
  return CryptoJS.AES.encrypt(note, CryptoJS.enc.Utf8.parse(k), { mode: CryptoJS.mode.ECB });
}
