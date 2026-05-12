// frontend/src/api.js

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
const API_TIMEOUT_MS = 5000;
const MAX_EMAIL_BODY_CHARS = 10_000;

export async function analyzeDetect(input) {
  const payload = { ...input };
  if (payload.email_ctx) {
    payload.email_ctx = {
      ...payload.email_ctx,
      body_text: payload.email_ctx.body_text
        ? payload.email_ctx.body_text.slice(0, MAX_EMAIL_BODY_CHARS)
        : '',
      body_html: payload.email_ctx.body_html
        ? payload.email_ctx.body_html.slice(0, MAX_EMAIL_BODY_CHARS * 2)
        : null,
    };
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), API_TIMEOUT_MS);

  try {
    const response = await fetch(`${API_URL}/detect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`Server returned ${response.status}`);
    }

    return await response.json();
  } catch (err) {
    if (err.name === 'AbortError') {
      throw new Error('Scan timed out');
    }
    // Network failures: TypeError with "Failed to fetch" message,
    // or sometimes empty message. Either way, the backend is unreachable.
    if (err.name === 'TypeError') {
      throw new Error('Cannot reach the scanner backend. Please try again later.');
    }
    throw err;
  } finally {
    clearTimeout(timeoutId);
  }
}

export function analyzeUrl(url) {
  return analyzeDetect({ url });
}

export function analyzeEmail(emailCtx) {
  return analyzeDetect({ email_ctx: emailCtx });
}