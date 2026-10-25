import AsyncStorage from '@react-native-async-storage/async-storage';

export async function signIn(email: string, password: string) {
  const res = await fetch('https://api.example.com/login', { method: 'POST', body: JSON.stringify({ email, password }) });
  const body = await res.json();
  console.log('login response', body);
  if (__DEV__) {
    console.debug('signed in as', email);
  }
  await AsyncStorage.setItem('lastEmail', email);
  console.info(`session ready for ${email}`);
  return body;
}
