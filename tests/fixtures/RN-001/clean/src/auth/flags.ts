import AsyncStorage from '@react-native-async-storage/async-storage';
import * as SecureStore from 'expo-secure-store';
import * as Keychain from 'react-native-keychain';
import { encrypt } from './crypto';

const TOKEN_KEY = 'auth_token';

// AsyncStorage.setItem('authToken', token) used to live here.
const note = "AsyncStorage.setItem('token', value)";

export async function saveFlags(expiresAt: number, fcm: string, apns: string): Promise<void> {
  await AsyncStorage.setItem('tokenExpiresAt', String(expiresAt));
  await AsyncStorage.setItem('hasSeenPasswordTip', 'true');
  await AsyncStorage.setItem('pushToken', fcm);
  await AsyncStorage.setItem('fcmToken', fcm);
  await AsyncStorage.setItem('deviceToken', apns);
  await AsyncStorage.multiSet([['theme', 'dark'], ['locale', 'en']]);
}

export async function readToken(): Promise<string | null> {
  return AsyncStorage.getItem(TOKEN_KEY);
}

export async function clearToken(): Promise<void> {
  await AsyncStorage.removeItem(TOKEN_KEY);
}

export async function saveSecurely(token: string, user: string, password: string): Promise<void> {
  await SecureStore.setItemAsync('authToken', token);
  await Keychain.setGenericPassword(user, password);
  await AsyncStorage.setItem('authToken', await encrypt(token));
}

export function webOnly(token: string): void {
  localStorage.setItem('token', token);
}

export { note };
