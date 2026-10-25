import Config from 'react-native-config';

it('reads the secret', () => {
  expect(Config.API_SECRET).toBeUndefined();
});
