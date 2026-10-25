export default ({ config }) => ({
  ...config,
  updates: {
    url: 'http://updates.example.com/api/manifest',
    codeSigningCertificate: './certs/certificate.pem',
    codeSigningMetadata: { keyid: 'main', alg: 'rsa-v1_5-sha256' },
  },
});
