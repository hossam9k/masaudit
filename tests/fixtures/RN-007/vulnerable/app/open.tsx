import { useLocalSearchParams } from 'expo-router';
import { WebView } from 'react-native-webview';

export default function Open() {
  const { target } = useLocalSearchParams<{ target: string }>();
  return <WebView source={{ uri: target }} />;
}
