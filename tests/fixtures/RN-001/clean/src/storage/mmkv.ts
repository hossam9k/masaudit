import { MMKV, createMMKV } from 'react-native-mmkv';
import { buildConfiguration, getKeyFromKeychain } from './config';

const secure = new MMKV({ id: 'secure', encryptionKey: getKeyFromKeychain() });
const other = createMMKV(buildConfiguration());
const plain = new MMKV({ id: 'prefs' });

export function save(jwt: string, password: string): void {
  secure.set('jwt', jwt);
  other.set('password', password);
  plain.set('theme', 'dark');
  plain.set('tokenExpiry', Date.now());
}
