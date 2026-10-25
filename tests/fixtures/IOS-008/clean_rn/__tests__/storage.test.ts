import * as Keychain from 'react-native-keychain';

test('legacy', async () => {
  await Keychain.setGenericPassword('u', 'p', { accessible: Keychain.ACCESSIBLE.ALWAYS });
});
