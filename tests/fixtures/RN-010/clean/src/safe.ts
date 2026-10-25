// eval(userInput) in a comment is not a call.
const globalObject = new Function('return this')();
const msg = 'do not eval(x) here';

export function handle(text: string, refresh: () => void) {
  const data = JSON.parse(text);
  setTimeout(refresh, 1000);
  setTimeout(() => refresh(), 1000);
  const engine = { eval: (s: string) => s };
  engine.eval(text);
  return { data, globalObject, msg };
}

type Callback = Function;
export const cb: Callback = () => {};

if (__DEV__) {
  // debug helpers are scope-lowered, not dropped; keep this clean fixture silent anyway
}
