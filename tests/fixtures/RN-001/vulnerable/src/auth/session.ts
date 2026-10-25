import { storage } from '../storage/mmkv';
import { createMMKV } from 'react-native-mmkv';

const kv = createMMKV({ id: 'auth' });

export function keepSession(t: string, p: string): void {
  storage.set('sessionToken', t);
  kv.set('password', p);
}
