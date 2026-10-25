export async function login(user: string, password: string) {
  if (typeof password === 'string' && password.length > 0) {
    const res = await fetch('https://api.demo.example/login', {
      method: 'POST',
      credentials: 'include',
      body: JSON.stringify({ user, password }),
    });
    return res.ok;
  }
  return false;
}

export function sameAsConfirmation(password: string, confirmPassword: string) {
  return password === confirmPassword;
}

export function isEmpty(init: { credentials?: string }) {
  return init.credentials === 'same-origin';
}
