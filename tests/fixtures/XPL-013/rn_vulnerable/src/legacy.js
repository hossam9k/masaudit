import CryptoJS from 'crypto-js';
import crypto from 'react-native-quick-crypto';

export const wrap = (text, pass) => CryptoJS.TripleDES.encrypt(text, pass).toString();

export function rc4(key, data) {
  return crypto.createCipheriv('rc4', key, '').update(data);
}
