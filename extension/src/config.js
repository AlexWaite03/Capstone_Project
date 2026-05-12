// Centralized config for the extension. Switches between dev and prod
// based on the Vite mode at build time.

//const isDev = import.meta.env.DEV;

export const API_URL = 'http://localhost:8000';

export const WEB_APP_URL = 'http://localhost:5173';

// How long to trust a cached scan result before re-scanning.
export const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

// Hard cap on email body length sent to the API.
export const MAX_EMAIL_BODY_CHARS = 10_000;

// Network timeout for API calls. Fail open after this.
export const API_TIMEOUT_MS = 5000;

// Domains we trust without scanning. Saves API calls and avoids
// false-positive warnings on common sites.
export const SAFE_DOMAINS = [
  'google.com',
  'youtube.com',
  'github.com',
  'wikipedia.org',
  'mozilla.org',
  'microsoft.com',
  'apple.com',
];