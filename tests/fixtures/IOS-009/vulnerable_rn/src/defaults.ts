import * as Keychain from 'react-native-keychain';

// No accessible option: react-native-keychain uses AFTER_FIRST_UNLOCK.
export const saveSession = (token: string) =>
  Keychain.setInternetCredentials('api.bank.example', 'session', token, { securityLevel: Keychain.SECURITY_LEVEL.ANY });
