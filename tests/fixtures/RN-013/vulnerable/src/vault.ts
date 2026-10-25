import CryptoJS from 'crypto-js';
import { getPin } from './pin';

const SECRET = 'my-app-passphrase';

export function seal(note: string) {
  return CryptoJS.AES.encrypt(note, SECRET).toString();
}

export function open(blob: string) {
  return CryptoJS.AES.decrypt(blob, getPin()).toString(CryptoJS.enc.Utf8);
}

export function sealWithPassword(note: string, password: string) {
  return CryptoJS.AES.encrypt(note, password, { format: CryptoJS.format.OpenSSL }).toString();
}
