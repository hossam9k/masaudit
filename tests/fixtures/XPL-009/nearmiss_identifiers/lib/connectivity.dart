// Captive-portal checks use plain HTTP on purpose: the redirect is what they look for.
const connectionTestUrls = [
  "http://captive.apple.com/hotspot-detect.html",
  "http://connectivitycheck.gstatic.com/generate_204",
  "http://www.gstatic.com/generate_204",
  "http://cp.cloudflare.com",
];
