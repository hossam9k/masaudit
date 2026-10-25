import { Linking } from 'react-native';

// Apple's documented Maps link: iOS hands it to the Maps app, so no request goes out over HTTP.
export function openInAppleMaps(address: string, lat: number, lng: number) {
  return Linking.openURL(`http://maps.apple.com/?q=${encodeURIComponent(address)}&ll=${lat},${lng}`);
}
