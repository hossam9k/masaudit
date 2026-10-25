import * as Keychain from 'react-native-keychain';
import { ACCESSIBLE, setInternetCredentials } from 'react-native-keychain';
import * as SecureStore from 'expo-secure-store';

export async function saveToken(server: string, token: string) {
  await Keychain.setGenericPassword('session', token, { accessible: Keychain.ACCESSIBLE.AFTER_FIRST_UNLOCK });
  await setInternetCredentials(server, 'user', token, { accessible: ACCESSIBLE.WHEN_UNLOCKED });
  await SecureStore.setItemAsync('refresh', token, { keychainAccessible: SecureStore.AFTER_FIRST_UNLOCK });
}
