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

1. Ensure backend, frontend and extension are already running.
    Backend:    pip install -r requirements.txt
                python -m src.api.api
                uvicorn src.api.api:app -reload
   Frontend:    npm install
                npm run dev
   Extension:   npm install
                npm run build
2. Go to Chrome => Manage extensions and turn on Developer mode (toggle in top right).
3. Select "Load unpacked" and choose the extension/dist folder.
4. Turn extension on and refresh.

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