import CryptoJS from 'crypto-js';
import QuickCrypto from 'react-native-quick-crypto';

// ECB is never used: CryptoJS.mode.ECB stays out of this file.
export function seal(text: string, key: CryptoJS.lib.WordArray) {
  const iv = CryptoJS.lib.WordArray.random(16);
  return CryptoJS.AES.encrypt(text, key, { iv, mode: CryptoJS.mode.CBC }).toString();
}

export function sealNative(key: Buffer, iv: Buffer, data: Buffer) {
  const c = QuickCrypto.createCipheriv('aes-256-gcm', key, iv);
  return Buffer.concat([c.update(data), c.final()]);
}

export const label = 'aes-256-ecb is not allowed here';
