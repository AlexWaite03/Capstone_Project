import { useEffect, useState } from 'react';
import { ScannerView } from '@frontend/App';
import { WEB_APP_URL } from '../shared/config.js';
import './popup.css';

function openWebApp(path = '') {
  chrome.tabs.create({ url: `${WEB_APP_URL}${path}` });
}

export default function Popup() {
  const [currentTab, setCurrentTab] = useState(null);

  /* On mount, ask the background worker what it knows about the active tab. */
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [tab] = await chrome.tabs.query({
          active: true,
          currentWindow: true,
        });
        if (!tab || cancelled) return;
        const state = await chrome.runtime.sendMessage({
          type: 'GET_TAB_STATE',
          tabId: tab.id,
        });
        if (!cancelled) setCurrentTab({ tab, state });
      } catch {
        /* No state yet, not an error */
      }
    })();
    return () => { cancelled = true; };
  }, []);

  return (
    <div className="popup-theme popup-shell">
      <header className="popup-topbar">
        <div className="popup-brand">
          <span className="popup-at">@</span>
          <span>CyberLang</span>
        </div>
        <button className="popup-open-app" onClick={() => openWebApp()}>
          Open full app ↗
        </button>
      </header>

      {currentTab?.state?.result && (
        <CurrentTabBanner state={currentTab.state} />
      )}

      <ScannerView />

      <footer className="popup-footer">
        <FooterLink onClick={() => openWebApp('/works')}>How it Works</FooterLink>
        <span className="popup-footer-dot">·</span>
        <FooterLink onClick={() => openWebApp('/about')}>About</FooterLink>
      </footer>
    </div>
  );
}

function CurrentTabBanner({ state }) {
  const { result, error } = state;
  if (error) {
    return <div className="popup-tab-banner warn">Current tab couldn't be scanned</div>;
  }
  const tier =
    result.riskLabel === 'High Risk' ? 'high' :
    result.riskLabel === 'Medium Risk' ? 'med' :
    'low';
  return (
    <div className={`popup-tab-banner ${tier}`}>
      <strong>Current tab:</strong> {result.riskLabel} · {result.percentage}%
    </div>
  );
}

function FooterLink({ onClick, children }) {
  return (
    
      <a href="#"
      onClick={(e) => { e.preventDefault(); onClick(); }}
      className="popup-footer-link"
    >
      {children}
    </a>
  );
}