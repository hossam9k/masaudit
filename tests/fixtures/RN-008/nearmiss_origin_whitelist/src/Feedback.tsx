// The WebView only loads Typeform pages, so only they can send messages.
import { WebView, WebViewMessageEvent } from 'react-native-webview';

export function Feedback({ formUrl, track }) {
  const onMessage = (event: WebViewMessageEvent) => {
    const data = JSON.parse(event.nativeEvent.data);
    track(data.event, data.step);
  };
  return <WebView source={{ uri: formUrl }} originWhitelist={["https://*.typeform.com"]} onMessage={onMessage} />;
}
