import { Linking } from 'react-native';
// The deep-link handler, called by the native layer with the incoming URL.
export function handleDeepLink(url: string) { const next = new URL(url).searchParams.get('next') || ''; Linking.openURL(next); }
