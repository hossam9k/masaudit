import CryptoJS from 'crypto-js';

export function seal(text: string, key: CryptoJS.lib.WordArray) {
  const iv = CryptoJS.lib.WordArray.random(16);
  return { iv: iv.toString(), data: CryptoJS.AES.encrypt(text, key, { iv }).toString() };
}

export function open(data: string, key: CryptoJS.lib.WordArray, ivHex: string) {
  return CryptoJS.AES.decrypt(data, key, { iv: CryptoJS.enc.Hex.parse(ivHex) });
}
