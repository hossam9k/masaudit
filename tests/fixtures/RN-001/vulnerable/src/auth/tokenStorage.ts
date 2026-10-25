import AsyncStorage from '@react-native-async-storage/async-storage';

const TOKEN_KEY = 'auth_token';
const STORAGE_KEY = 'login';
const KEYS = { refresh: 'refresh_token' };

export async function saveSession(token: string, refresh: string): Promise<void> {
  await AsyncStorage.setItem(TOKEN_KEY, token);
  await AsyncStorage.multiSet([['@user', '{}'], [KEYS.refresh, refresh]]);
}

export async function savePassword(password: string): Promise<void> {
  await AsyncStorage.setItem('@user_password', password);
}

export async function saveLogin(res: { data: { accessToken: string } }): Promise<void> {
  await AsyncStorage.setItem(STORAGE_KEY, res.data.accessToken);
}
