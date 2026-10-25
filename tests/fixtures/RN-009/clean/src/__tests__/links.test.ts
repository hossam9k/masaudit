import { Linking } from 'react-native';
Linking.addEventListener('url', ({ url }) => Linking.openURL(url));
