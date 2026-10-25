import Reactotron from 'reactotron-react-native';

Reactotron.configure({ host: '192.168.1.20' })
  .useReactNative()
  .connect();
