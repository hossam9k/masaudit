import { WebView } from 'react-native-webview';

export function HelpScreen({ route }) {
  return <WebView source={{ uri: route.params.url }} />;
}
