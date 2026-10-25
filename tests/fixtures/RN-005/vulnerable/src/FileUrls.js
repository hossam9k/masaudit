import RNWebView from 'react-native-webview';

export default function Viewer({ page }) {
  return (
    <RNWebView
      source={{ uri: page }}
      allowFileAccessFromFileURLs={true}
    />
  );
}
