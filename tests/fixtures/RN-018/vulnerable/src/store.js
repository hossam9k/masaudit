import { createStore, applyMiddleware } from 'redux';
import { composeWithDevTools } from 'remote-redux-devtools';
import rootReducer from './reducers';

const composeEnhancers = composeWithDevTools({ realtime: true, hostname: '10.0.2.2', port: 8000 });
export const store = createStore(rootReducer, composeEnhancers(applyMiddleware()));
