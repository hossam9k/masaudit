import { addPlugin } from 'react-native-flipper';

export function startFlipper() {
  if (!__DEV__) {
    return;
  }
  addPlugin({ getId() { return 'inspector'; }, onConnect() {}, onDisconnect() {} });
}
