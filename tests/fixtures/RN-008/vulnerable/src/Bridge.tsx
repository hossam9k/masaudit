import { WebView, WebViewMessageEvent } from 'react-native-webview';
import { API_BASE_URL } from './config';

function handleAction(action: string, payload: unknown) {
  console.log(action, payload);
}

export function Help() {
  const onMessage = (event: WebViewMessageEvent) => {
    const data = JSON.parse(event.nativeEvent.data);
    handleAction(data.action, data.payload);
  };
  return <WebView source={{ uri: `${API_BASE_URL}/help` }} onMessage={onMessage} />;
}

export function Inline({ url }) {
  return (
    <WebView
      source={{ uri: url }}
      onMessage={({ nativeEvent }) => {
        const msg = JSON.parse(nativeEvent.data);
        if (msg.type === 'pay') pay(msg.amount);
      }}
    />
  );
}
