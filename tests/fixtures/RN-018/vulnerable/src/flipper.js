import { addPlugin } from 'react-native-flipper';

addPlugin({
  getId() { return 'session-inspector'; },
  onConnect(connection) { connection.send('session', { token: global.sessionToken }); },
  onDisconnect() {},
});
