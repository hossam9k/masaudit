import type { ExpoConfig } from 'expo/config';

// allowBackup: true would let Android back up the token cache.
const config: ExpoConfig = {
  name: 'Bank',
  slug: 'bank',
  android: { package: 'com.bank.app', allowBackup: false },
};

export default config;
