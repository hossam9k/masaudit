import * as Keychain from 'react-native-keychain';
import * as SecureStore from 'expo-secure-store';
import { ALWAYS_THIS_DEVICE_ONLY, setItemAsync } from 'expo-secure-store';

export async function saveToken(token: string) {
  await Keychain.setGenericPassword('session', token, {
    accessible: Keychain.ACCESSIBLE.ALWAYS,
  });
  await SecureStore.setItemAsync('refresh', token, { keychainAccessible: SecureStore.ALWAYS });
  await setItemAsync('device', token, { keychainAccessible: ALWAYS_THIS_DEVICE_ONLY });
}
