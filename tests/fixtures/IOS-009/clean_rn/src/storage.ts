import * as Keychain from 'react-native-keychain';
import * as SecureStore from 'expo-secure-store';
import { buildOptions } from './options';
import { storage } from './mmkv';

export async function saveToken(server: string, token: string) {
  await Keychain.setGenericPassword('session', token, { accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY });
  await Keychain.setInternetCredentials(server, 'user', token, buildOptions(server));
  await Keychain.setInternetCredentials(server, 'user2', token, { ...buildOptions(server), securityLevel: 1 });
  await SecureStore.setItemAsync('refresh', token, {
    keychainAccessible: SecureStore.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY,
  });
  storage.setItem('theme', 'dark');
}
