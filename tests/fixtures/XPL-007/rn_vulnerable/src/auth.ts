import CryptoJS from 'crypto-js';

export function hashPassword(password: string) {
  return CryptoJS.MD5(password).toString();
}
