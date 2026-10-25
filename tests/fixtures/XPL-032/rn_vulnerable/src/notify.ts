import notifee from '@notifee/react-native';
import * as Notifications from 'expo-notifications';

export async function showOtp(otp: string) {
  await notifee.displayNotification({ title: 'Sign-in', body: `Your code is ${otp}` });
}

export async function showBalance(balance: string) {
  await Notifications.scheduleNotificationAsync({
    content: { title: 'Account', body: `Balance: ${balance}` },
    trigger: null,
  });
}
