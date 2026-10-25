import { applyMiddleware, createStore, Middleware } from 'redux';
import thunk from 'redux-thunk';
import logger from 'redux-logger';
import { startNetworkLogging } from 'react-native-network-logger';
import { reducer } from './reducer';

const middleware: Middleware[] = [thunk];
if (__DEV__) {
  middleware.push(logger);
}
const devOnly = __DEV__ ? [logger] : [];

__DEV__ && startNetworkLogging();

export const store = createStore(reducer, applyMiddleware(...middleware, ...devOnly));
