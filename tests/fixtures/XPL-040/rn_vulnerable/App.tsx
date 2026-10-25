import * as Updates from 'expo-updates';

// An over-the-air JS update is not a forced store update.
export async function refresh() {
  const res = await Updates.checkForUpdateAsync();
  return res.isAvailable;
}
