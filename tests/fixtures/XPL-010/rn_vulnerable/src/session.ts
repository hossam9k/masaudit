import AsyncStorage from '@react-native-async-storage/async-storage';

export async function restore(user: { accessToken: string }) {
  const t = await AsyncStorage.getItem('@auth_token');
  console.log('DEBUG auth token =', t);
  console.info(`restored session ${user.accessToken}`);
  console.debug('login', { password: user.accessToken });
}
