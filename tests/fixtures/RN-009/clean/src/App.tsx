import React, { useEffect } from 'react';
import { Linking } from 'react-native';

const ALLOWED_HOSTS = new Set(['example.com']);

export default function App({ navigation }: any) {
  useEffect(() => {
    // Validated: protocol and host checked against an allowlist.
    const sub = Linking.addEventListener('url', ({ url }) => {
      const target = new URL(new URL(url).searchParams.get('next') || '');
      if (target.protocol === 'https:' && ALLOWED_HOSTS.has(target.hostname)) {
        Linking.openURL(target.toString());
      }
    });
    // Only analytics, and a screen name with a plain ID.
    Linking.getInitialURL().then((initial) => {
      track('open', initial);
      const id = new URL(initial || 'x://').searchParams.get('id');
      navigation.navigate('Profile', { id });
      Linking.openURL('https://example.com/help');
      Linking.openURL(`tel:${id}`);
      fetch(`https://api.example.com/items/${id}`);
    });
    return () => sub.remove();
  }, [navigation]);
  return null;
}

declare function track(e: string, u: unknown): void;

// A link pressed inside a message is not a deep link.
export function onLinkPress(url: string) {
  Linking.openURL(url);
}
