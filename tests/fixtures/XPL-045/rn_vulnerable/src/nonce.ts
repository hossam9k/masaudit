export function newRequest() {
  const nonce = Date.now().toString(16);
  return { nonce, state: `${new Date().getTime()}` };
}
