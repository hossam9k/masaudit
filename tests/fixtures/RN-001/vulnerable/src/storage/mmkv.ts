import { MMKV } from 'react-native-mmkv';

export const storage = new MMKV();

export function saveJwt(jwt: string): void {
  storage.set('jwt', jwt);
}
