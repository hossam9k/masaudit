import axios from 'axios';

export const api = axios.create({ baseURL: 'https://api.example.com' });

api.interceptors.request.use((config) => {
  console.log('Request', config.headers);
  return config;
});
