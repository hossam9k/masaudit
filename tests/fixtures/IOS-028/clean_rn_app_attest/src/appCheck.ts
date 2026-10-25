import { initializeAppCheck, ReactNativeFirebaseAppCheckProvider } from '@react-native-firebase/app-check';
import { getApp } from '@react-native-firebase/app';

const provider = new ReactNativeFirebaseAppCheckProvider();
provider.configure({
  android: { provider: __DEV__ ? 'debug' : 'playIntegrity' },
  apple: { provider: __DEV__ ? 'debug' : 'appAttestWithDeviceCheckFallback' },
});

export const appCheck = initializeAppCheck(getApp(), { provider, isTokenAutoRefreshEnabled: true });
