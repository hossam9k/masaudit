import { applyMiddleware, createStore } from 'redux';
import { configureStore } from '@reduxjs/toolkit';
import thunk from 'redux-thunk';
import logger, { createLogger } from 'redux-logger';
import { reducer } from './reducer';

export const store = createStore(reducer, applyMiddleware(thunk, logger));

const log = createLogger({ collapsed: true });
export const store2 = configureStore({ reducer, middleware: (gdm) => gdm().concat(log) });
