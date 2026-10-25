import { WebView } from 'react-native-webview';

export const Promo = () => (
  <WebView source={{ uri: 'https://promo.example.com' }} originWhitelist={['*']} />
);
