import { createStore, applyMiddleware, compose } from 'redux';
import { composeWithDevTools } from 'remote-redux-devtools';
import rootReducer from './reducers';

const composeEnhancers = __DEV__ ? composeWithDevTools({ realtime: true, port: 8000 }) : compose;
export const store = createStore(rootReducer, composeEnhancers(applyMiddleware()));
