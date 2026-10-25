import React, { useEffect, useState } from 'react';
import { Linking } from 'react-native';
import { WebView } from 'react-native-webview';
import { routeLink } from './services/links';

export default function App({ navigation }: any) {
  const [page, setPage] = useState<string | null>(null);

  useEffect(() => {
    const sub = Linking.addEventListener('url', ({ url }) => {
      const next = new URL(url).searchParams.get('next') || '';
      Linking.openURL(next);
    });
    Linking.getInitialURL().then((initial) => {
      if (initial) setPage(new URL(initial).searchParams.get('page'));
    });
    return () => sub.remove();
  }, []);

  useEffect(() => {
    (async () => {
      const link = await Linking.getInitialURL();
      if (link) routeLink(link, navigation);
    })();
  }, [navigation]);

  return page ? <WebView source={{ uri: page }} /> : null;
}
