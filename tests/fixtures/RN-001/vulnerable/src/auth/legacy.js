import { AsyncStorage } from 'react-native';

export function remember(t) {
  return AsyncStorage.setItem('userToken', t);
}
