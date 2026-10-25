import Config from 'react-native-config';
import { WebView } from 'react-native-webview';

const HELP_URL = 'https://help.example.com';

export const A = ({ id }) => <WebView source={{ uri: `https://help.example.com/a/${id}` }} />;
export const B = () => <WebView source={{ uri: Config.HELP_URL }} />;
export const C = () => <WebView source={{ uri: HELP_URL }} />;
export const D = ({ route }) => <WebView source={{ uri: `${HELP_URL}/${route.params.slug}` }} />;
export const E = ({ url }) => <WebView source={{ uri: url }} />;
