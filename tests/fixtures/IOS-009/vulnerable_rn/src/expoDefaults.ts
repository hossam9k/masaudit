import * as SecureStore from 'expo-secure-store';

// No keychainAccessible: expo-secure-store uses WHEN_UNLOCKED.
export const saveRefresh = (token: string) => SecureStore.setItemAsync('refresh', token);
