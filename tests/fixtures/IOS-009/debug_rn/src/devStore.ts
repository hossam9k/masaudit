import * as Keychain from 'react-native-keychain';

// Reported in debug scope: only development builds run it.
export async function saveDebugToken(token: string) {
  if (__DEV__) {
    await Keychain.setGenericPassword('debug', token, { accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED });
  }
}
