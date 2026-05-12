// Gmail content script.
//
// Watches for an open email, extracts subject/sender/body, sends to the
// background worker for scanning, and injects a banner above the email body
// with the result.
//
// IMPORTANT: Gmail's class names are auto-generated and DO rotate. The
// selectors below are what worked at time of writing. If the extension
// stops finding emails, inspect Gmail's DOM and update SELECTORS.
//
// The script fails silently on selector misses — better to do nothing than
// spam errors into the user's console.

const SELECTORS = {
  // The email body container in the reading pane.
  body: '.a3s.aiL',
  // Sender chip on the open email.
  sender: '.gD',
  // Subject line at the top of the open email.
  subject: 'h2.hP',
};

const BANNER_ATTR = 'data-cyberlang-banner';
const SCANNED_ATTR = 'data-cyberlang-scanned';

// Throttle scans: don't re-scan the same DOM node within this window.
const SCAN_THROTTLE_MS = 1000;
let lastScanTime = 0;

function maybeScanOpenEmail() {
  const now = Date.now();
  if (now - lastScanTime < SCAN_THROTTLE_MS) return;

  const bodyEl = document.querySelector(SELECTORS.body);
  if (!bodyEl || bodyEl.hasAttribute(SCANNED_ATTR)) return;

  const senderEl = document.querySelector(SELECTORS.sender);
  const subjectEl = document.querySelector(SELECTORS.subject);

  // Require body + sender so we don't scan chrome UI by accident.
  if (!senderEl) return;

  bodyEl.setAttribute(SCANNED_ATTR, 'true');
  lastScanTime = now;

  // Try to grab attachment names if visible.
  const attachmentEls = document.querySelectorAll('.aQy, .aZo');
  const attachmentNames = Array.from(attachmentEls)
    .map(el => el.getAttribute('download_url') || el.textContent?.trim())
    .filter(Boolean);

  const emailCtx = {
    from_addr: senderEl.getAttribute('email') || '',
    display_name: senderEl.getAttribute('name') || null,
    subject: subjectEl?.textContent.trim() || null,
    body_text: bodyEl.innerText || bodyEl.textContent || '',
    body_html: bodyEl.innerHTML || null,
    attachment_names: attachmentNames,
    // The following are NOT visible in Gmail's DOM:
    reply_to: null,
    return_path: null,
    message_id: null,
  };

  // Send to background. We don't await — the response handler injects the banner.
  chrome.runtime.sendMessage(
    { type: 'EMAIL_CONTENT', payload: emailCtx },
    (response) => {
      if (chrome.runtime.lastError) return;           // Background may be reloading; silently skip.
      if (!response?.ok) {
        injectErrorBanner(bodyEl, response?.error || 'Scanner server unavailable.');
        return;
      }
      injectBanner(bodyEl, response.result);
    }
  );
}


function injectBanner(emailEl, result) {
  // Don't double-inject.
  //if (emailEl.previousElementSibling?.hasAttribute(BANNER_ATTR)) return;
  if (emailEl.parentNode.querySelector(`[${BANNER_ATTR}]`)) return;

  const banner = document.createElement('div');
  banner.setAttribute(BANNER_ATTR, 'true');

  const bg =
    result.riskLabel === 'High Risk' ? '#fee2e2' :
    result.riskLabel === 'Medium Risk' ? '#fef9c3' :
    '#dcfce7';
  const border =
    result.riskLabel === 'High Risk' ? '#fca5a5' :
    result.riskLabel === 'Medium Risk' ? '#fbbf24' :
    '#86efac';
  const icon =
    result.riskLabel === 'High Risk' ? '⚠️' :
    result.riskLabel === 'Medium Risk' ? '⚡' :
    '✓';

  banner.style.cssText = `
    padding: 10px 14px;
    margin: 8px 0;
    border-radius: 6px;
    font-family: system-ui, -apple-system, sans-serif;
    font-size: 13px;
    background: ${bg};
    border: 1px solid ${border};
    color: #111;
    display: flex;
    align-items: center;
    gap: 8px;
  `;

  banner.innerHTML = `
    <span style="font-size: 18px;">${icon}</span>
    <span>
      <strong>CyberLang:</strong> ${result.riskLabel}
      (${result.percentage}% phishing likelihood)
    </span>
  `;

  emailEl.parentNode.insertBefore(banner, emailEl);
}

function injectErrorBanner(emailEl, error) {
  // Don't double-inject.
  //if (emailEl.previousElementSibling?.hasAttribute(BANNER_ATTR)) return;
  if (emailEl.parentNode.querySelector(`[${BANNER_ATTR}]`)) return;

  const banner = document.createElement('div');
  banner.setAttribute(BANNER_ATTR, 'true');

  banner.style.cssText = `
    padding: 10px 14px;
    margin: 8px 0;
    border-radius: 6px;
    font-family: system-ui, -apple-system, sans-serif;
    font-size: 13px;
    background: #fee2e2;
    border: 1px solid #fca5a5;
    color: #991b1b;
    display: flex;
    align-items: center;
    gap: 8px;
  `;

  banner.innerHTML = `
    <span style="font-size: 18px;">⚠️</span>
    <span>
      <strong>CyberLang:</strong> ${error}. Please try again later.
    </span>
  `;

  emailEl.parentNode.insertBefore(banner, emailEl);
}

// Watch the DOM for new emails being opened.
const observer = new MutationObserver(() => {
  maybeScanOpenEmail();
});

observer.observe(document.body, {
  childList: true,
  subtree: true,
});

// Run once at start in case an email is already open.
maybeScanOpenEmail();