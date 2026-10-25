import { useRef } from 'react';
import { WebView } from 'react-native-webview';

export function Greeting({ userName }) {
  return (
    <WebView
      source={{ html: '<h1>Hi</h1>' }}
      injectedJavaScript={`document.title='${userName}';true;`}
    />
  );
}

export function Search({ query }) {
  const ref = useRef(null);
  const run = () => ref.current?.injectJavaScript("window.search('" + query + "'); true;");
  return <WebView ref={ref} source={{ uri: 'https://search.example.com' }} onLoadEnd={run} />;
}
