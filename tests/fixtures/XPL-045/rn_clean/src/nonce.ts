export function newSession(token: string) {
  return { token, createdAt: Date.now(), expiresAt: Date.now() + 3600_000 };
}

export const isTokenFresh = (token: { issuedAt: number }) => Date.now() - token.issuedAt < 60_000;
