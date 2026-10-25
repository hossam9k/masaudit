import * as LocalAuthentication from 'expo-local-authentication';
import ReactNativeBiometrics from 'react-native-biometrics';

export async function unlock(setUnlocked: (v: boolean) => void) {
  const { success } = await LocalAuthentication.authenticateAsync({ promptMessage: 'Unlock' });
  if (success) setUnlocked(true);
}

export async function confirmPayment() {
  const rnBiometrics = new ReactNativeBiometrics();
  const { success } = await rnBiometrics.simplePrompt({ promptMessage: 'Confirm' });
  return success;
}
