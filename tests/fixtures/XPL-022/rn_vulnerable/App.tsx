import JailMonkey from 'jail-monkey';

// jail-monkey alone is root detection, not debugger detection
export const rooted = JailMonkey.isJailBroken();
