import * as Keychain from 'react-native-keychain';
import * as SecureStore from 'expo-secure-store';

// Never use Keychain.ACCESSIBLE.ALWAYS here: it is readable before the first unlock.
export async function saveToken(token: string) {
  await Keychain.setGenericPassword('session', token, {
    accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  });
  await SecureStore.setItemAsync('refresh', token, { keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY });
}

export function isLegacy(level: string) {
  return level === Keychain.ACCESSIBLE.ALWAYS;
}
