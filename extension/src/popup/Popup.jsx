// popup.jsx
import { useEffect, useState } from 'react';
import { useScanner } from '@shared/useScanner';
import { WEB_APP_URL } from '../config.js';
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
          <img src="/icons/logo_16.png" alt="" className="popup-logo" />
          <span>CyberLang Scanner</span>
        </div>
        <button className="popup-open-app" onClick={() => openWebApp()}>
          Open full app ↗
        </button>
      </header>

      {currentTab?.state?.result && (
        <CurrentTabBanner state={currentTab.state} />
      )}

      <section className="popup-scanner scanner-hero">
        <h1>Hybrid Phishing & Scam Detection</h1>
          <p className="subtitle">Analyze URLs & Email Text with Automata & Machine Learning</p>
      </section>

      <ScannerPanel />

      <footer className="popup-footer">
        <FooterLink onClick={() => openWebApp('/works')}>How it Works</FooterLink>
        <span className="popup-footer-dot">·</span>
        <FooterLink onClick={() => openWebApp('/about')}>About</FooterLink>
      </footer>
    </div>
  );
}

/* ---------- Scanner panel ---------- */

function ScannerPanel() {
  const [scanType, setScanType] = useState('URL');
  const [inputValue, setInputValue] = useState('');

  const { loading, scanResult, scanError, analyze, reset } = useScanner();

  const handleAnalyze = () => analyze({ scanType, inputValue });

  const handleSwitchType = (type) => {
    setScanType(type);
    setInputValue('');
    reset();
  };

  return (
    <section className="popup-scanner">
      <div className="slider-box">
        <button
          className={`slider-btn ${scanType === 'URL' ? 'active' : ''}`}
          onClick={() => handleSwitchType('URL')}
        >
          URL Scan
        </button>
        <button
          className={`slider-btn ${scanType === 'Email' ? 'active' : ''}`}
          onClick={() => handleSwitchType('Email')}
        >
          Email Text Analysis
        </button>
      </div>

      {!loading && (
        <>
          {scanType === 'URL' ? (
            <input
              type="text"
              className="scan-field"
              placeholder="https://suspicious-bank-login.com/"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
            />
          ) : (
            <textarea
              className="scan-field email-field"
              placeholder="Paste email text here..."
              rows="4"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
            />
          )}

          <button className="big-analyze-btn" onClick={handleAnalyze}>
            Analyze
          </button>
        </>
      )}

      {loading && (
        <div className="loading-view">
          <div className="loader-container">
            <div className="scanner-ring"></div>
            <div className="scanner-line"></div>
          </div>
          <h2 className="loading-text">SCANNING...</h2>
          <p className="loading-sub">Running DFA + ML Classification Engine</p>
        </div>
      )}

      {!loading && scanError && (
        <div className="error-box">{scanError}</div>
      )}

      {!loading && !scanError && scanResult && (
        <ScanResultBox result={scanResult} />
      )}
    </section>
  );
}

/* ---------- Result + helper components ---------- */

function ScanResultBox({ result }) {
  return (
    <div className="result-box">
      <h2>{result.riskLabel}</h2>
      <h1>{result.percentage}%</h1>
      <p>Likelihood this {result.scanType} is phishing</p>

      {result.matchedRules.length > 0 && (
        <>
          <h3>Why?</h3>
          <ul>
            {result.matchedRules.slice(0, 3).map((rule, i) => (
              <li key={i}>{formatRule(rule)}</li>
            ))}
          </ul>
          {result.matchedRules.length > 3 && (
            <details>
              <summary>Matched rules ({result.matchedRules.length})</summary>
              <ul>
                {result.matchedRules.map((rule, i) => (
                  <li key={i}>{formatRule(rule)}</li>
                ))}
              </ul>
            </details>
          )}
        </>
      )}
    </div>
  );
}

function formatRule(rule) {
  return typeof rule === 'string' ? rule : `${rule.id}: ${rule.description}`;
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
    <a
      href="#"
      onClick={(e) => { e.preventDefault(); onClick(); }}
      className="popup-footer-link"
    >
      {children}
    </a>
  );
}