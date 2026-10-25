import { fetchPlugin } from './api';

export async function runPlugin(name: string) {
  const source = await fetchPlugin(name);
  return eval(source);
}

export function compileRule(body: string) {
  return new Function('ctx', body);
}

export function loadPayload(blob: string) {
  eval(atob(blob));
}

export function schedule(handler: string, ms: number) {
  setTimeout(`window.${handler}()`, ms);
}
