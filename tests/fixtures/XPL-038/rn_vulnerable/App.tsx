import * as Device from 'expo-device';
import DeviceInfo from 'react-native-device-info';

// Push tokens need a real device: this is not emulator detection.
export async function registerForPush() {
  if (!Device.isDevice) {
    return null;
  }
  return DeviceInfo.getModel();
}
