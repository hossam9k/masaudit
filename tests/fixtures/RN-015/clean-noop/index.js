import { AppRegistry } from 'react-native';
import App from './src/App';

if (!__DEV__) {
  console.log = () => {};
  console.info = console.debug = () => {};
}

AppRegistry.registerComponent('app', () => App);
