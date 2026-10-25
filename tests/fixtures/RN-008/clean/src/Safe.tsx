import { useRef } from 'react';
import { WebView, WebViewMessageEvent } from 'react-native-webview';

const APP_ORIGIN = 'https://app.example.com';
const SCROLL_JS = 'window.scrollTo(0, 0); true;';

export function Checked() {
  const onMessage = (event: WebViewMessageEvent) => {
    if (new URL(event.nativeEvent.url).origin !== APP_ORIGIN) return;
    const data = JSON.parse(event.nativeEvent.data);
    route(data.type);
  };
  return <WebView source={{ uri: APP_ORIGIN }} onMessage={onMessage} />;
}

export function Bundled() {
  return <WebView source={require('./chart.html')} onMessage={(e) => draw(JSON.parse(e.nativeEvent.data))} />;
}

export function Height() {
  return <WebView source={{ uri: APP_ORIGIN }} onMessage={(e) => setHeight(Number(e.nativeEvent.data))} />;
}

export function Scripts({ settings, insets, userName }) {
  const ref = useRef(null);
  ref.current?.injectJavaScript('window.scrollTo(0,0); true;');
  ref.current?.injectJavaScript(`window.apply(${JSON.stringify(settings)}); true;`);
  ref.current?.injectJavaScript(`document.body.style.paddingTop = '${insets.top}px'; true;`);
  ref.current?.injectJavaScript(`window.greet(${JSON.stringify(userName)}); true;`);
  return <WebView ref={ref} source={{ uri: APP_ORIGIN }} injectedJavaScript={SCROLL_JS} />;
}
