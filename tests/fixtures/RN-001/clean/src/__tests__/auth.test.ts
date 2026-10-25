import AsyncStorage from '@react-native-async-storage/async-storage';

it('stores the token', async () => {
  await AsyncStorage.setItem('authToken', 'abc');
});
