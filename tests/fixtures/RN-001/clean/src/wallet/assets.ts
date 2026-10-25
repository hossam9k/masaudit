import AsyncStorage from '@react-native-async-storage/async-storage';

export async function saveAssets(tokens: string[], selected: string, hidden: string[]): Promise<void> {
  await AsyncStorage.setItem('tokens', JSON.stringify(tokens));
  await AsyncStorage.setItem('selectedToken', selected);
  await AsyncStorage.setItem('hiddenTokens', JSON.stringify(hidden));
  await AsyncStorage.setItem('tokenList', JSON.stringify(tokens));
}
