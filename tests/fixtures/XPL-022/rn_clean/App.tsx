import JailMonkey from 'jail-monkey';

export async function attached() {
  return JailMonkey.isDebuggedMode();
}
