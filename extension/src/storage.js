// Storage helpers. Wraps chrome.storage.local with consistent key prefixes
// so we don't accidentally collide keys or scatter naming conventions.
//
// Key prefixes:
//   scan:<url>      Cached scan results, TTL'd
//   tab:<tabId>     Current scan state per tab
//   history:<ts>    History entries (most recent first)
//   prefs           User preferences (single object)

import { CACHE_TTL_MS, SAFE_DOMAINS } from './config.js';

// ---------- URL scan cache ----------

export async function getCachedScan(url) {
  const key = `scan:${url}`;
  const stored = await chrome.storage.local.get(key);
  const entry = stored[key];
  if (!entry) return null;
  if (Date.now() - entry.timestamp > CACHE_TTL_MS) return null;
  return entry.result;
}

export async function setCachedScan(url, result) {
  const key = `scan:${url}`;
  await chrome.storage.local.set({
    [key]: { result, timestamp: Date.now() },
  });
}

// ---------- Per-tab state (for badge + popup) ----------

export async function setTabState(tabId, state) {
  await chrome.storage.local.set({ [`tab:${tabId}`]: state });
}

export async function getTabState(tabId) {
  const key = `tab:${tabId}`;
  const stored = await chrome.storage.local.get(key);
  return stored[key] || null;
}

export async function clearTabState(tabId) {
  await chrome.storage.local.remove(`tab:${tabId}`);
}

// ---------- Safe-domain check ----------

export function isSafeDomain(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    return SAFE_DOMAINS.some(
      (d) => hostname === d || hostname.endsWith('.' + d)
    );
  } catch {
    return false;
  }
}

// ---------- Scannable URL check ----------

export function isScannableUrl(url) {
  if (!url) return false;
  if (!url.startsWith('http://') && !url.startsWith('https://')) return false;
  try {
    const parsed = new URL(url);
    // Skip localhost and private IPs
    const host = parsed.hostname;
    if (host === 'localhost' || host === '127.0.0.1') return false;
    if (host.startsWith('192.168.') || host.startsWith('10.')) return false;
    return true;
  } catch {
    return false;
  }
}