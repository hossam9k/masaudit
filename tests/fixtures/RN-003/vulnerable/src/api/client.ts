import axios from 'axios';

export const api = axios.create({ baseURL: 'https://api.example.com' });

api.interceptors.request.use((config) => {
  console.log('Request', config.method, config.headers);
  return config;
});

api.interceptors.response.use(
  (response) => {
    console.log(JSON.stringify(response.data));
    return response;
  },
  (error) => Promise.reject(error),
);

axios.interceptors.response.use(undefined, (error) => {
  console.error(error);
  return Promise.reject(error);
});

function logRequest(config) {
  console.debug(config);
  return config;
}

axios.interceptors.request.use(logRequest);
