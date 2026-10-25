import CryptoJS from 'crypto-js';

export const wrap = (text, key, iv) => CryptoJS.AES.encrypt(text, key, { iv }).toString();
export const names = { DES: 'retired', RC4: 'retired' };
