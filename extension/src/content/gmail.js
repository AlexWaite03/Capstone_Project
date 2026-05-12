// Gmail content script.
//
// Watches for an open email, extracts subject/sender/body, sends to the
// background worker for scanning, and injects a banner above the email body
// with the result.
//
// Gmail's class names are auto-generated and DO rotate. If the extension
// stops finding emails, inspect Gmail's DOM and update SELECTORS.

const SELECTORS = {
  body: '.a3s.aiL',         // open email body
  sender: '.gD',            // sender chip
  subject: 'h2.hP',         // subject heading
};

const BANNER_ATTR = 'data-cyberlang-banner';
const SCANNED_ATTR = 'data-cyberlang-scanned';

const SCAN_THROTTLE_MS = 1000;
let lastScanTime = 0;

function maybeScanOpenEmail() {
  const now = Date.now();
  if (now - lastScanTime < SCAN_THROTTLE_MS) return;

  const bodyEl = document.querySelector(SELECTORS.body);
  if (!bodyEl || bodyEl.hasAttribute(SCANNED_ATTR)) return;

  const senderEl = document.querySelector(SELECTORS.sender);
  const subjectEl = document.querySelector(SELECTORS.subject);

  // Require sender so we don't scan stray Gmail UI.
  if (!senderEl) return;

  bodyEl.setAttribute(SCANNED_ATTR, 'true');
  lastScanTime = now;

  // Payload matches what the service worker forwards to analyzeEmail.
  const emailCtx = {
    from_addr: senderEl.getAttribute('email') || '',
    subject: subjectEl?.textContent.trim() || null,
    body_text: bodyEl.innerText || bodyEl.textContent || '',
  };

  chrome.runtime.sendMessage(
    { type: 'EMAIL_CONTENT', payload: emailCtx },
    (response) => {
      if (chrome.runtime.lastError) return; // worker reloading; silent skip
      if (!response?.ok) {
        injectErrorBanner(bodyEl, response?.error);
        return;
      }
      injectBanner(bodyEl, response.result);
    }
  );
}

// ---------- Banner injection ----------

function bannerAlreadyPresent(emailEl) {
  // Look in the parent rather than just previousElementSibling to accomodate for Gmail re-rendering
  return emailEl.parentNode?.querySelector(`[${BANNER_ATTR}]`) != null;
}

function bannerStyles(riskLabel) {
  if (riskLabel === 'High Risk') {
    return { bg: '#fee2e2', border: '#fca5a5', icon: '⚠️' };
  }
  if (riskLabel === 'Medium Risk') {
    return { bg: '#fef9c3', border: '#fbbf24', icon: '⚡' };
  }
  return { bg: '#dcfce7', border: '#86efac', icon: '✓' };
}

function buildBanner({ bg, border, color = '#111', icon, html }) {
  const banner = document.createElement('div');
  banner.setAttribute(BANNER_ATTR, 'true');
  banner.style.cssText = `
    padding: 10px 14px;
    margin: 8px 0;
    border-radius: 6px;
    font-family: system-ui, -apple-system, sans-serif;
    font-size: 13px;
    background: ${bg};
    border: 1px solid ${border};
    color: ${color};
    display: flex;
    align-items: center;
    gap: 8px;
  `;
  banner.innerHTML = `<span style="font-size: 18px;">${icon}</span><span>${html}</span>`;
  return banner;
}

function injectBanner(emailEl, result) {
  if (bannerAlreadyPresent(emailEl)) return;

  const { bg, border, icon } = bannerStyles(result.riskLabel);
  const rules = result.matchedRules || [];

  const rulesHtml = rules.length > 0
    ? `
      <div style="margin-top: 6px; font-size: 12px; color: #374151;">
        <strong>Why?</strong>
        <ul style="margin: 4px 0 0; padding-left: 18px;">
          ${rules.slice(0, 3).map(r => `<li>${formatRule(r)}</li>`).join('')}
        </ul>
        ${rules.length > 3 ? `<div style="margin-top: 4px; opacity: 0.7;">+ ${rules.length - 3} more</div>` : ''}
      </div>
    `
    : '';

  const banner = document.createElement('div');
  banner.setAttribute(BANNER_ATTR, 'true');
  banner.style.cssText = `
    padding: 10px 14px;
    margin: 8px 0;
    border-radius: 6px;
    font-family: system-ui, -apple-system, sans-serif;
    font-size: 13px;
    background: ${bg};
    border: 1px solid ${border};
    color: #111;
  `;
  banner.innerHTML = `
    <div style="display: flex; align-items: center; gap: 8px;">
      <span style="font-size: 18px;">${icon}</span>
      <span><strong>CyberLang:</strong> ${result.riskLabel} (${result.percentage}% phishing likelihood)</span>
    </div>
    ${rulesHtml}
  `;

  emailEl.parentNode.insertBefore(banner, emailEl);
}

function formatRule(rule) {
  if (typeof rule === 'string') return rule;
  return `${rule.id}: ${rule.description}`;
}

function injectErrorBanner(emailEl, errorMessage) {
  if (bannerAlreadyPresent(emailEl)) return;

  const message = errorMessage
    ? `Couldn't scan this email — ${errorMessage}`
    : `Scanner server unavailable. Please try again later.`;

  const banner = buildBanner({
    bg: '#fee2e2',
    border: '#fca5a5',
    color: '#991b1b',
    icon: '❌',
    html: `<strong>CyberLang:</strong> ${message}`,
  });

  emailEl.parentNode.insertBefore(banner, emailEl);
}

// ---------- DOM watching ----------

const observer = new MutationObserver(() => {
  maybeScanOpenEmail();
});

observer.observe(document.body, {
  childList: true,
  subtree: true,
});

// Run once at start in case an email is already open.
maybeScanOpenEmail();