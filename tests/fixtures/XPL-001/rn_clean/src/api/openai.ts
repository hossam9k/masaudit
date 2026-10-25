import Config from 'react-native-config';

// The key stays on our server; the app calls our proxy.
export function ask(q: string) {
  return fetch(`${Config.API_URL}/ask`, { method: 'POST', body: JSON.stringify({ input: q }) });
}
// const OLD_KEY = '{{FAKE_OPENAI_KEY}}';
