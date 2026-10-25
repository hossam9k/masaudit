import analytics from '@react-native-firebase/analytics';
import * as Sentry from '@sentry/react-native';

export async function onLogin(user: { id: string; plan: string }) {
  await analytics().setUserId(user.id);
  await analytics().setUserProperties({ plan: user.plan });
  Sentry.setUser({ id: user.id });
}
