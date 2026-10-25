import { AppRegistry } from 'react-native';
import App from './App';

if (__DEV__) {
  require('./ReactotronConfig');
}

AppRegistry.registerComponent('Wallet', () => App);
