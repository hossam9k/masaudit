import * as LocalAuthentication from 'expo-local-authentication';

// LocalAuthentication.authenticateAsync() in a comment does not count.
export async function canUseBiometrics() {
  return (await LocalAuthentication.hasHardwareAsync()) && (await LocalAuthentication.isEnrolledAsync());
}

// Another library's authenticate() is not a biometric prompt.
import { authenticate } from './api';
export const login = (u: string, p: string) => authenticate(u, p);
