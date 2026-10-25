// Not crypto-js: another library's AES object.
import { AES } from './my-native-aes';
export const run = (d: string, k: string) => AES.encrypt(d, k);
