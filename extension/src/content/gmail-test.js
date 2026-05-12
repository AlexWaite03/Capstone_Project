// Gmail content script.
//
// Watches for an open email, extracts subject/sender/body, sends to the
// background worker for scanning, and injects a banner above the email body
// with the result.
//
// The banner now supports:
//   - An expandable dropdown showing the rules/reasons that fired.
//   - Inline highlighting of suspicious phrases inside the email body.
//   - Hover-tooltips on highlights showing which rule matched.
//   - Click-to-scroll: clicking a reason in the dropdown scrolls to the
//     first matching highlight and briefly pulses it.
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
const HIGHLIGHT_ATTR = 'data-cyberlang-highlight';

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
      highlightMatches(bodyEl, response.result.reasons || []);
    }
  );
}


// ---------------------------------------------------------------------------
// Banner
// ---------------------------------------------------------------------------

function injectBanner(emailEl, result) {
  // Don't double-inject.
  if (emailEl.parentNode.querySelector(`[${BANNER_ATTR}]`)) return;

  const banner = document.createElement('div');
  banner.setAttribute(BANNER_ATTR, 'true');

  const palette = paletteFor(result.riskLabel);
  const icon =
    result.riskLabel === 'High Risk' ? '⚠️' :
    result.riskLabel === 'Medium Risk' ? '⚡' :
    '✓';

  banner.style.cssText = `
    margin: 8px 0;
    border-radius: 6px;
    font-family: system-ui, -apple-system, sans-serif;
    font-size: 13px;
    background: ${palette.bg};
    border: 1px solid ${palette.border};
    color: #111;
    overflow: hidden;
  `;

  const reasons = Array.isArray(result.reasons) ? result.reasons : [];
  const hasReasons = reasons.length > 0;

  // Header row: icon + label + (optional) toggle.
  const header = document.createElement('div');
  header.style.cssText = `
    padding: 10px 14px;
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: ${hasReasons ? 'pointer' : 'default'};
    user-select: none;
  `;
  header.innerHTML = `
    <span style="font-size: 18px;">${icon}</span>
    <span style="flex: 1;">
      <strong>CyberLang:</strong> ${escapeHtml(result.riskLabel)}
      (${escapeHtml(String(result.percentage))}% phishing likelihood)
    </span>
    ${hasReasons ? `
      <span class="cyberlang-toggle" style="
        font-size: 12px;
        color: #444;
        display: flex;
        align-items: center;
        gap: 4px;
      ">
        <span class="cyberlang-toggle-label">Show ${reasons.length} detail${reasons.length === 1 ? '' : 's'}</span>
        <span class="cyberlang-chevron" style="
          display: inline-block;
          transition: transform 0.15s ease;
        ">▾</span>
      </span>
    ` : ''}
  `;
  banner.appendChild(header);

  // Details panel (hidden by default).
  if (hasReasons) {
    const details = document.createElement('div');
    details.className = 'cyberlang-details';
    details.style.cssText = `
      display: none;
      padding: 0 14px 12px 14px;
      border-top: 1px solid ${palette.border};
      background: rgba(255, 255, 255, 0.4);
    `;
    details.appendChild(buildReasonsList(reasons, emailEl));
    banner.appendChild(details);

    header.addEventListener('click', () => {
      const open = details.style.display === 'block';
      details.style.display = open ? 'none' : 'block';
      const chevron = header.querySelector('.cyberlang-chevron');
      const label = header.querySelector('.cyberlang-toggle-label');
      if (chevron) chevron.style.transform = open ? 'rotate(0deg)' : 'rotate(180deg)';
      if (label) label.textContent = open
        ? `Show ${reasons.length} detail${reasons.length === 1 ? '' : 's'}`
        : `Hide details`;
    });
  }

  emailEl.parentNode.insertBefore(banner, emailEl);
}

function buildReasonsList(reasons, emailEl) {
  const list = document.createElement('ul');
  list.style.cssText = `
    margin: 10px 0 0 0;
    padding: 0;
    list-style: none;
    display: flex;
    flex-direction: column;
    gap: 8px;
  `;

  reasons.forEach((reason, i) => {
    const item = document.createElement('li');
    const sev = severityOf(reason);
    const sevPalette = severityPalette(sev);

    item.style.cssText = `
      padding: 8px 10px;
      background: #fff;
      border: 1px solid #e5e7eb;
      border-left: 3px solid ${sevPalette.border};
      border-radius: 4px;
      cursor: pointer;
    `;

    const matches = Array.isArray(reason.matches) ? reason.matches : [];
    const matchPreview = matches.length
      ? `<div style="margin-top: 4px; font-size: 12px; color: #555;">
           Matched: ${matches.slice(0, 3).map(m =>
             `<code style="background: ${sevPalette.bg}; padding: 1px 4px; border-radius: 3px;">${escapeHtml(m)}</code>`
           ).join(' ')}
           ${matches.length > 3 ? `<span style="color: #888;">+${matches.length - 3} more</span>` : ''}
         </div>`
      : '';

    item.innerHTML = `
      <div style="font-weight: 600; font-size: 13px;">
        ${escapeHtml(reason.rule || reason.id || `Rule ${i + 1}`)}
      </div>
      ${reason.description ? `
        <div style="font-size: 12px; color: #444; margin-top: 2px;">
          ${escapeHtml(reason.description)}
        </div>` : ''}
      ${matchPreview}
    `;

    item.addEventListener('click', (e) => {
      e.stopPropagation();
      scrollToFirstMatch(emailEl, reason);
    });

    list.appendChild(item);
  });

  return list;
}

function injectErrorBanner(emailEl, error) {
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
      <strong>CyberLang:</strong> ${escapeHtml(error)}. Please try again later.
    </</span>
  `;

  emailEl.parentNode.insertBefore(banner, emailEl);
}


// ---------------------------------------------------------------------------
// Highlights
// ---------------------------------------------------------------------------

// Walk the email body's text nodes and wrap matches of any reason.matches[]
// phrase in a styled <mark>. Each highlight stores its rule id so the
// reason-list can scroll to it.
function highlightMatches(emailEl, reasons) {
  if (!Array.isArray(reasons) || reasons.length === 0) return;

  // Build a flat list of { phrase, reason } pairs, longest-first so we don't
  // partially-match inside a longer phrase.
  const phrases = [];
  for (const reason of reasons) {
    const matches = Array.isArray(reason.matches) ? reason.matches : [];
    for (const m of matches) {
      if (typeof m === 'string' && m.trim().length > 0) {
        phrases.push({ phrase: m, reason });
      }
    }
  }
  phrases.sort((a, b) => b.phrase.length - a.phrase.length);
  if (phrases.length === 0) return;

  // Combined regex of all phrases (escaped), case-insensitive.
  const pattern = new RegExp(
    '(' + phrases.map(p => escapeRegex(p.phrase)).join('|') + ')',
    'gi'
  );

  // Map lowercase phrase → reason for quick lookup once a match is found.
  const phraseToReason = new Map();
  for (const { phrase, reason } of phrases) {
    const k = phrase.toLowerCase();
    if (!phraseToReason.has(k)) phraseToReason.set(k, reason);
  }

  // Walk text nodes only — never touch element nodes, never re-wrap.
  const walker = document.createTreeWalker(emailEl, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      if (!node.nodeValue || !node.nodeValue.trim()) return NodeFilter.FILTER_REJECT;
      // Skip text already inside a highlight or inside <script>/<style>.
      let p = node.parentNode;
      while (p && p !== emailEl) {
        if (p.nodeType === 1) {
          const tag = p.tagName;
          if (tag === 'SCRIPT' || tag === 'STYLE') return NodeFilter.FILTER_REJECT;
          if (p.hasAttribute && p.hasAttribute(HIGHLIGHT_ATTR)) return NodeFilter.FILTER_REJECT;
        }
        p = p.parentNode;
      }
      return NodeFilter.FILTER_ACCEPT;
    },
  });

  const textNodes = [];
  let n;
  while ((n = walker.nextNode())) textNodes.push(n);

  for (const textNode of textNodes) {
    const text = textNode.nodeValue;
    pattern.lastIndex = 0;
    if (!pattern.test(text)) continue;
    pattern.lastIndex = 0;

    const frag = document.createDocumentFragment();
    let lastIdx = 0;
    let match;
    while ((match = pattern.exec(text)) !== null) {
      const matchedText = match[0];
      const start = match.index;
      const end = start + matchedText.length;

      if (start > lastIdx) {
        frag.appendChild(document.createTextNode(text.slice(lastIdx, start)));
      }

      const reason = phraseToReason.get(matchedText.toLowerCase());
      frag.appendChild(buildHighlightNode(matchedText, reason));

      lastIdx = end;
    }
    if (lastIdx < text.length) {
      frag.appendChild(document.createTextNode(text.slice(lastIdx)));
    }

    textNode.parentNode.replaceChild(frag, textNode);
  }
}

function buildHighlightNode(text, reason) {
  const sev = severityOf(reason);
  const palette = severityPalette(sev);

  const mark = document.createElement('mark');
  mark.setAttribute(HIGHLIGHT_ATTR, reason?.id || reason?.rule || '');
  mark.textContent = text;
  mark.title = reason?.rule
    ? `${reason.rule}${reason.description ? ' — ' + reason.description : ''}`
    : 'Suspicious phrase';
  mark.style.cssText = `
    background: ${palette.bg};
    border-bottom: 2px solid ${palette.border};
    padding: 0 2px;
    border-radius: 2px;
    cursor: help;
  `;
  return mark;
}

function scrollToFirstMatch(emailEl, reason) {
  const id = reason?.id || reason?.rule || '';
  if (!id) return;
  const target = emailEl.querySelector(`[${HIGHLIGHT_ATTR}="${cssEscape(id)}"]`);
  if (!target) return;
  target.scrollIntoView({ behavior: 'smooth', block: 'center' });

  // Brief pulse to draw the eye.
  const original = target.style.boxShadow;
  target.style.transition = 'box-shadow 0.3s ease';
  target.style.boxShadow = '0 0 0 3px rgba(59, 130, 246, 0.5)';
  setTimeout(() => { target.style.boxShadow = original; }, 900);
}


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function paletteFor(riskLabel) {
  if (riskLabel === 'High Risk')   return { bg: '#fee2e2', border: '#fca5a5' };
  if (riskLabel === 'Medium Risk') return { bg: '#fef9c3', border: '#fbbf24' };
  return { bg: '#dcfce7', border: '#86efac' };
}

function severityOf(reason) {
  const s = (reason?.severity || '').toLowerCase();
  if (s === 'high' || s === 'medium' || s === 'low') return s;
  return 'medium'; // sensible default
}

function severityPalette(sev) {
  if (sev === 'high')   return { bg: '#fecaca', border: '#dc2626' };
  if (sev === 'low')    return { bg: '#dcfce7', border: '#16a34a' };
  return                       { bg: '#fef08a', border: '#ca8a04' };
}

function escapeHtml(s) {
  return String(s)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function cssEscape(s) {
  if (window.CSS && CSS.escape) return CSS.escape(s);
  return String(s).replace(/[^a-zA-Z0-9_-]/g, '\\$&');
}


// ---------------------------------------------------------------------------
// Observer
// ---------------------------------------------------------------------------

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