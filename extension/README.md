# CyberLang Scanner — Browser Extension

Browser extension that scans URLs and Gmail messages for phishing risk using
the CyberLang FastAPI backend.

## What it does

1. **Popup scanner** — paste a URL or email text, get a risk rating.
2. **Tab navigation interception** — before a page loads, scan its URL;
   if High Risk, show a warning.
3. **Gmail scanning** — when you open an email in Gmail, inject a banner
   above the body with its risk rating.


## Setup

### 1. Frontend prerequisite

The popup imports `ScannerView` from `../frontend/src/App.jsx`. That export
must exist. In your frontend's `App.jsx`:

```jsx
export function ScannerView() {
  // ... scanner state, handleAnalyze, JSX
}

export default function App() {
  // ... uses <ScannerView /> internally
}
```

### 2. Backend changes

Open `api_additions.py` and copy the two pieces into your `api.py`:
- CORS middleware
- `/scan` wrapper endpoint

Restart FastAPI: `uvicorn api:app --reload`.

### 3. Install + build the extension

```bash
cd extension
npm install
npm run build
```

This produces `extension/dist/`.

### 4. Load in Chrome

1. Open `chrome://extensions`
2. Enable "Developer mode" (top right)
3. Click "Load unpacked" → select `extension/dist/`
4. Pin the extension to the toolbar
5. **Copy the extension ID** shown under the extension's name

### 5. Allow the extension origin in CORS

Edit `api.py` and replace `chrome-extension://YOUR_EXTENSION_ID` with the
real ID from step 4. Restart FastAPI.

### 6. Add icons

Place 16/32/48/128 px PNG icons in `extension/public/icons/`. The build
copies them into `dist/icons/`.

## Dev workflow

After code changes:

```bash
npm run build
```

Then in `chrome://extensions`, click the reload icon on your extension card.

For HMR on the popup specifically (the only piece HMR really helps with):

```bash
npm run dev
```

The background service worker and content script still require a rebuild +
extension reload to pick up changes.

## How the pieces talk to each other

```
                         user navigates to URL
                                  │
                                  ▼
                webNavigation.onBeforeNavigate (background.js)
                                  │
                ┌─────────────────┴─────────────────┐
                │ check cache → call /scan → cache  │
                └─────────────────┬─────────────────┘
                                  │
                ┌─────────────────┴─────────────────┐
                │ High Risk?                        │
                │   yes → redirect to warning.html  │
                │   no  → update toolbar badge      │
                └───────────────────────────────────┘

                       user opens Gmail email
                                  │
                                  ▼
            MutationObserver fires (content/gmail.js)
                                  │
              extracts {from_addr, subject, body_text}
                                  │
            sendMessage('EMAIL_CONTENT') → background.js
                                  │
                       calls /detect on API
                                  │
            sendResponse → content script injects banner

                       user clicks toolbar icon
                                  │
                                  ▼
                       popup.html opens
                                  │
                Popup component renders ScannerView
                                  │
              GET_TAB_STATE → shows current tab's status
```

## Testing checklist

### Popup (manual scan)
- [ ] Normal URL (e.g., `https://example.com`) → result shown
- [ ] Long URL → result shown, no UI breakage
- [ ] URL shortener (`https://bit.ly/...`) → result shown
- [ ] Punycode (`xn--...`) → result shown
- [ ] %xx-encoded URL → handled
- [ ] Empty input → "Please enter..." alert
- [ ] Invalid URL → "Please enter a valid URL." alert
- [ ] Email text under 10 chars → "Email text is too short." alert
- [ ] API offline → friendly error in popup, no infinite loading

### Navigation interception (background)
- [ ] Known phishing URL → warning.html shown
- [ ] Safe URL (e.g., google.com) → no interruption, green badge
- [ ] Repeat visit within 24h → uses cache (verify no API call in Network tab)
- [ ] `chrome://`, `file://` URLs → ignored, no errors
- [ ] localhost → ignored
- [ ] API timeout (5s) → fail open, badge shows "?"
- [ ] Tab closed before scan completes → no error spam

### Warning page
- [ ] Shows URL and risk percentage correctly
- [ ] "Go back" returns to previous page
- [ ] "Proceed anyway" prompts confirmation, then navigates
- [ ] No way to recursively warn on warning.html itself

### Gmail
- [ ] Benign personal email → green banner, Low Risk
- [ ] OTP/verification email → not falsely flagged
- [ ] Phishing-template email → red banner, High Risk
- [ ] Banner appears in reading-pane mode
- [ ] Banner appears in full-page email view
- [ ] Switching between emails injects new banner, not duplicates
- [ ] Gmail layout changed and selectors fail → silent failure, no console spam

### Edge cases
- [ ] Two rapid navigations to same URL → only one API call
- [ ] Extension reloaded mid-scan → no orphaned UI state
- [ ] Install-time permission prompt is acceptable (review the warning)

## Known limitations

- **Gmail selectors are fragile.** Google rotates class names. If banners
  stop appearing, inspect Gmail's DOM and update `SELECTORS` in
  `src/content/gmail.js`.
- **Pre-navigation scanning isn't synchronous.** `webNavigation` can't
  block; the warning page replaces the dangerous page once the scan
  returns (typically <1s for cached URLs, ~1-2s for fresh).
- **`<all_urls>` host permission** is a heavy install-time prompt. Users
  will see "Read your browsing history" / "Read and change all your data on
  all websites." Required for the navigation interception feature.
- **No offline mode.** If the API is unreachable, scans fail open.
