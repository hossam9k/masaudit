// originWhitelist allows every https page, so any of them can send messages.
import { WebView, WebViewMessageEvent } from 'react-native-webview';

export function Feedback({ formUrl, pay }) {
  const onMessage = (event: WebViewMessageEvent) => {
    const data = JSON.parse(event.nativeEvent.data);
    pay(data.amount);
  };
  return <WebView source={{ uri: formUrl }} originWhitelist={["https://*"]} onMessage={onMessage} />;
}
