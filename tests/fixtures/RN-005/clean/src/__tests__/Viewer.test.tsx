import { WebView } from 'react-native-webview';

it('renders', () => {
  render(<WebView source={{ uri: 'file:///x' }} allowUniversalAccessFromFileURLs />);
});
