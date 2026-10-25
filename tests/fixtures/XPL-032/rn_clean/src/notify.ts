import notifee, { AndroidVisibility } from '@notifee/react-native';

export async function showOtp(otp: string) {
  await notifee.displayNotification({
    title: 'Sign-in',
    body: `Your code is ${otp}`,
    android: { channelId: 'otp', visibility: AndroidVisibility.PRIVATE },
  });
}

export async function showNews() {
  await notifee.displayNotification({ title: 'News', body: 'New articles are waiting.' });
}
