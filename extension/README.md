# CyberLang Analytics Phishing Detection — Browser Extension

Browser extension that scans URLs and Gmail messages for phishing risk using
the CyberLang FastAPI backend.

## What it does

1. **Popup scanner** — paste a URL or email text, get a risk rating.
2. **Tab navigation interception** — before a page loads, scan its URL;
   if High Risk, show a warning.
3. **Gmail scanning** — when you open an email in Gmail, inject a banner
   above the body with its risk rating.

## Usage steps

1. Download extension zip file from [].
2. Unzip the file somewhere on your computer (a folder you won't delete — Chrome reads from this folder permanently).
3. Open `chrome://extensions` in Chrome (or go to Chrome => Manage extensions).
4. turn on **Developer mode** (toggle in top right).
5. Click **Load unpacked** and select the unzipped folder.
6. Pin the CyberLang Scanner icon to your toolbar.


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
