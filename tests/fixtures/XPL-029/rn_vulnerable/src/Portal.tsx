import React, { useRef } from 'react';
import { WebView } from 'react-native-webview';

export function Portal({ accessToken }: { accessToken: string }) {
  const ref = useRef<WebView>(null);
  const refresh = (sessionToken: string) => ref.current?.injectJavaScript(`window.session = '${sessionToken}'; true;`);
  return (
    <WebView
      ref={ref}
      source={{ uri: 'https://portal.demo.example' }}
      injectedJavaScriptBeforeContentLoaded={`window.authToken = '${accessToken}'; true;`}
      onLoadEnd={() => refresh(accessToken)}
    />
  );
}
