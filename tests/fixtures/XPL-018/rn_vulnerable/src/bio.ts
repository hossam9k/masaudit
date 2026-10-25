import * as Keychain from 'react-native-keychain';
import ReactNativeBiometrics from 'react-native-biometrics';
import * as LocalAuthentication from 'expo-local-authentication';

export const rnBiometrics = new ReactNativeBiometrics({ allowDeviceCredentials: true });

export function save(secret: string) {
  return Keychain.setGenericPassword('user', secret, {
    accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_ANY_OR_DEVICE_PASSCODE,
  });
}

export function unlock() {
  return LocalAuthentication.authenticateAsync({ disableDeviceFallback: false });
}
