import React from 'react';
import { startNetworkLogging } from 'react-native-network-logger';
import { Root } from './Root';

startNetworkLogging();

export default function App() {
  return <Root />;
}
