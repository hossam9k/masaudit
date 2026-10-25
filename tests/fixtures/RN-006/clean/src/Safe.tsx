import { WebView } from 'react-native-webview';

const HTML = '<h1>Terms</h1>';

export const A = () => <WebView source={{ uri: 'https://example.com' }} originWhitelist={['https://*']} />;
export const B = () => <WebView source={{ html: HTML }} originWhitelist={['*']} />;
export const C = () => <WebView source={require('./terms.html')} originWhitelist={['*']} />;
export const D = ({ name }) => <WebView source={{ html: `<p>${name}</p>` }} originWhitelist={['*']} />;
export const E = ({ url }) => <WebView source={{ uri: url }} originWhitelist={['https://app.example.com']} />;
export const F = ({ url }) => <WebView source={{ uri: url }} />;
// export const G = () => <WebView source={{ uri: 'https://x.example' }} originWhitelist={['*']} />;
