import analytics from '@react-native-firebase/analytics';
import * as Sentry from '@sentry/react-native';

export async function onLogin(user: { id: string; email: string; phone: string }) {
  await analytics().setUserId(user.email);
  await analytics().setUserProperties({ phone: user.phone });
  Sentry.setUser({ id: user.id, email: user.email });
}
