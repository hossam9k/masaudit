export async function signIn(email: string) {
  const res = await fetch('https://api.example.com/login', { method: 'POST', body: JSON.stringify({ email }) });
  console.log('login status', res.status);
  return res.json();
}
