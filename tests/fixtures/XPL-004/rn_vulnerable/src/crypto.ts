import CryptoJS from 'crypto-js';
import QuickCrypto from 'react-native-quick-crypto';

export function seal(text: string, key: CryptoJS.lib.WordArray) {
  return CryptoJS.AES.encrypt(text, key, { mode: CryptoJS.mode.ECB }).toString();
}

export function sealNative(key: Buffer, data: Buffer) {
  const c = QuickCrypto.createCipheriv('aes-256-ecb', key, null);
  return Buffer.concat([c.update(data), c.final()]);
}
