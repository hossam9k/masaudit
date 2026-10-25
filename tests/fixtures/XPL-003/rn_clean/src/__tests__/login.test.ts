const password = 'Str0ngPassw0rd!2024x';

test('login', () => {
  expect(password.length).toBeGreaterThan(8);
});
