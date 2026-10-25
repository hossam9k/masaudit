import * as Keychain from 'react-native-keychain';
export const save = (t: string) =>
  Keychain.setGenericPassword('session', t, { accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_CURRENT_SET });
