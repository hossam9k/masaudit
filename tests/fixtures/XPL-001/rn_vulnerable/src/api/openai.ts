const OPENAI_KEY = '{{FAKE_OPENAI_KEY}}';

export function ask(q: string) {
  return fetch('https://api.openai.com/v1/responses', {
    method: 'POST',
    headers: { Authorization: `Bearer ${OPENAI_KEY}` },
    body: JSON.stringify({ input: q }),
  });
}
