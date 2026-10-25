import { initializeAppCheck, ReactNativeFirebaseAppCheckProvider } from '@react-native-firebase/app-check';
import { getApp } from '@react-native-firebase/app';

// No apple provider: React Native Firebase uses DeviceCheck on iOS, not App Attest.
const provider = new ReactNativeFirebaseAppCheckProvider();
provider.configure({ android: { provider: 'playIntegrity' } });

export const appCheck = initializeAppCheck(getApp(), { provider, isTokenAutoRefreshEnabled: true });
