import { useAsyncStorage } from '@react-native-async-storage/async-storage';

export function useAccessToken() {
  const { getItem, setItem } = useAsyncStorage('@access_token');
  return { getItem, save: (t: string) => setItem(t) };
}
