import { useRoute } from '@react-navigation/native';
import WebView from 'react-native-webview';

export default function ArticleScreen() {
  const route = useRoute();
  const { url, title = '' } = route.params;
  return <WebView source={{ uri: url, headers: { Authorization: `Bearer ${token}` } }} />;
}
