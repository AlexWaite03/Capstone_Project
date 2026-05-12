// Background service worker. Three jobs:
//   1. Intercept top-frame navigations, scan the URL, redirect to
//      warning.html if High Risk.
//   2. Update the toolbar badge for the active tab based on its scan result.
//   3. Handle scan requests forwarded from content scripts (Gmail).

import { analyzeUrl, analyzeEmail } from '@frontend/api.js';
import {
  getCachedScan,
  setCachedScan,
  setTabState,
  getTabState,
  clearTabState,
  isSafeDomain,
  isScannableUrl,
} from '../shared/storage.js';

// ---------- Installation ----------

chrome.runtime.onInstalled.addListener(() => {
  console.log('CyberLang Scanner installed');
});

// ---------- Navigation interception ----------

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only top-level frames. Skip iframes, subresources, prefetches.
  if (details.frameId !== 0) return;

  const { tabId, url } = details;

  if (!isScannableUrl(url)) return;

  // Don't re-warn on our own warning page.
  if (url.startsWith(chrome.runtime.getURL(''))) return;

  // Safe domains: mark green badge, skip API call.
  if (isSafeDomain(url)) {
    const result = { percentage: 0, riskLabel: 'Low Risk' };
    await setTabState(tabId, { url, result });
    updateBadge(tabId, result);
    return;
  }

  // Cache check.
  let result = await getCachedScan(url);

  if (!result) {
    try {
      result = await analyzeUrl(url);
      await setCachedScan(url, result);
    } catch (err) {
      console.warn('Scan failed; failing open:', err.message);
      await setTabState(tabId, { url, error: err.message });
      updateBadge(tabId, null, '?');
      return;
    }
  }

  await setTabState(tabId, { url, result });

  if (result.riskLabel === 'High Risk') {
    const warningUrl = chrome.runtime.getURL(
      `warning.html?url=${encodeURIComponent(url)}&risk=${result.percentage}`
    );
    try {
      await chrome.tabs.update(tabId, { url: warningUrl });
    } catch (err) {
      // Tab may have been closed before we got here. Not worth surfacing.
    }
  } else {
    updateBadge(tabId, result);
  }
});

// ---------- Tab activation: refresh badge ----------

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const state = await getTabState(tabId);
  if (state?.result) {
    updateBadge(tabId, state.result);
  } else {
    clearBadge(tabId);
  }
});

// ---------- Tab cleanup ----------

chrome.tabs.onRemoved.addListener((tabId) => {
  clearTabState(tabId);
});

// ---------- Badge helpers ----------

function updateBadge(tabId, result, overrideText) {
  if (overrideText) {
    chrome.action.setBadgeText({ tabId, text: overrideText });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#888' });
    return;
  }

  if (!result) {
    clearBadge(tabId);
    return;
  }

  const { riskLabel, percentage } = result;
  let color;
  if (riskLabel === 'High Risk') color = '#dc2626';
  else if (riskLabel === 'Medium Risk') color = '#f59e0b';
  else color = '#16a34a';

  chrome.action.setBadgeText({ tabId, text: `${percentage}` });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

function clearBadge(tabId) {
  chrome.action.setBadgeText({ tabId, text: '' });
}

// ---------- Message routing (from content script + popup) ----------

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'EMAIL_CONTENT') {
    // Gmail content script asking us to scan an email.
    analyzeEmail(message.payload)
      .then((result) => {
        // Cache last email scan for popup reference.
        chrome.storage.local.set({
          lastEmailScan: {
            result,
            from_addr: message.payload.from_addr,
            subject: message.payload.subject,
            timestamp: Date.now(),
          },
        });
        sendResponse({ ok: true, result });
      })
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true; // async response
  }

  if (message.type === 'GET_TAB_STATE') {
    // Popup asking what we know about the current tab.
    getTabState(message.tabId).then((state) => sendResponse(state));
    return true;
  }
});