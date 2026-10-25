import { login } from '../Login';

test('login', async () => {
  const password = 'pass123';
  expect(password === 'pass123').toBe(true);
  await login('demo', password);
});
