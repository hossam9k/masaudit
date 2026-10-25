import CryptoJS from 'crypto-js';

const iv = CryptoJS.enc.Utf8.parse('0000000000000000');

export function seal(text: string, key: CryptoJS.lib.WordArray) {
  return CryptoJS.AES.encrypt(text, key, { iv }).toString();
}

export function sealHex(text: string, key: CryptoJS.lib.WordArray) {
  return CryptoJS.AES.encrypt(text, key, { iv: CryptoJS.enc.Hex.parse('a1b2c3d4e5f60718293a4b5c6d7e8f90') });
}
