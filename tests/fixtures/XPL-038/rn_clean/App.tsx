import DeviceInfo from 'react-native-device-info';

export async function guard(blockApp: (why: string) => void) {
  if (await DeviceInfo.isEmulator()) {
    blockApp('emulator');
  }
}
