import axios from 'axios';
import { getToken } from './auth';

export const api = axios.create({ baseURL: 'https://api.example.com' });

api.interceptors.request.use(async (config) => {
  config.headers.Authorization = `Bearer ${await getToken()}`;
  return config;
});

api.interceptors.response.use((response) => {
  console.log('Response', response.status, response.config.url);
  return response;
});

api.interceptors.request.use((config) => {
  if (__DEV__) {
    console.log(config.headers);
  }
  return config;
});

if (__DEV__) {
  api.interceptors.response.use((r) => {
    console.log(JSON.stringify(r.data));
    return r;
  });
}

if (process.env.NODE_ENV !== 'production') {
  axios.interceptors.request.use((c) => {
    console.log(c);
    return c;
  });
}

// api.interceptors.request.use((c) => { console.log(c.headers); return c; });
