import styled from 'styled-components/native';
import { WebView as Browser } from 'react-native-webview';

const Page = styled(Browser)`
  flex: 1;
`;

export const Article = ({ link }) => <Page source={{ uri: link }} allowFileAccess />;
