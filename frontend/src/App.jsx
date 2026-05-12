import { useState } from 'react'
import { useScanner } from '@shared/useScanner'
import './App.css'

function App() {
  const [view, setView] = useState('scanner')
  const [scanType, setScanType] = useState('URL')
  const [showInfo, setShowInfo] = useState(false)
  const [inputValue, setInputValue] = useState('')

  // Updated Data Structure to include Names
  const teamMembers = [
    { name: "Daena Crosby", url: "https://res.cloudinary.com/dqvx0k9yy/image/upload/v1773955418/WhatsApp_Image_2026-03-17_at_7.36.25_AM_sf04kl.webp" },
    { name: "Hector RiettIe ", url: "https://res.cloudinary.com/dqvx0k9yy/image/upload/v1773955870/lol_blcyli.webp" },
    { name: "Shaine Bramwell", url: "https://res.cloudinary.com/dqvx0k9yy/image/upload/v1773955419/Screenshot_20260319_154621_ChatGPT.jpg_ccrch2.webp" },
    { name: "Nicole Johnson ", url: "https://res.cloudinary.com/dqvx0k9yy/image/upload/v1778464087/image_2026-05-10_204740553_vvtqiv.webp" },
    { name: "Alexander Waite", url: "https://res.cloudinary.com/dqvx0k9yy/image/upload/v1773956058/alexander_yhllbi.webp" }
  ];


  /* ================= VALIDATION + ANALYZE ================= */

  const { loading, scanResult, scanError, analyze } = useScanner()

  const handleAnalyze = () => analyze({ scanType, inputValue })

  return (
    <div className="container">
      
    {/* ================= NAVBAR ================= */}
    <nav className="navbar">
      <div className="logo-section">
        <img
          src="https://res.cloudinary.com/dqvx0k9yy/image/upload/v1774308532/logo_ms4dvf.png"
          alt="CyberLang Analytics Logo"
          className="logo-image"
        />
        <span className="logo-text">CyberLang Analytics</span>
      </div>
      <div className="nav-links">
        <button
          className={view === 'scanner' ? 'nav-item active' : 'nav-item'}
          onClick={() => setView('scanner')}
        >
          Scanner
        </button>
        <button
          className={view === 'works' ? 'nav-item active' : 'nav-item'}
          onClick={() => setView('works')}
        >
          How it Works
        </button>
        <button
          className={view === 'about' ? 'nav-item active' : 'nav-item'}
          onClick={() => setView('about')}
        >
          About Us
        </button>
      </div>
    </nav>

      {/* ================= SCANNER PAGE ================= */}
      {view === 'scanner' && (
        <main className="scanner-hero">
          <h1>Hybrid Phishing & Scam Detection</h1>
          <p className="subtitle">Analyze URLs & Email Text with Automata & Machine Learning</p>

          <div className="slider-box">
            <div className={`slider-active-overlay ${scanType === 'URL' ? 'left' : 'right'}`}></div>
            <button
              className={`slider-btn ${scanType === 'URL' ? 'active' : ''}`}
              onClick={() => { setScanType('URL'); setInputValue('') }}
            >
              URL Scan
            </button>
            <button
              className={`slider-btn ${scanType === 'Email' ? 'active' : ''}`}
              onClick={() => { setScanType('Email'); setInputValue('') }}
            >
              Email Text Analysis
            </button>
          </div>

          {!loading && (
            <>
              <div className="input-row">
                <div className="input-container">
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
                      rows="6"
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                    />
                  )}
                </div>

                <div className="info-anchor">
                  <div className="info-btn" onClick={() => setShowInfo(!showInfo)}>i</div>
                  {showInfo && (
                    <div className="info-message">
                      Our AI uses Formal Languages to check for known malicious patterns
                    </div>
                  )}
                </div>
              </div>

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

          {scanResult && !loading && (
            <div className="result-box">
              <h2>{scanResult.riskLabel}</h2>
              <h1>{scanResult.percentage}%</h1>
              <p>Likelihood this {scanResult.scanType} is phishing</p>

              {scanResult.matchedRules.length > 0 && (
                <>
                  <h3>Why?</h3>
                  <ul>
                    {scanResult.matchedRules.slice(0, 3).map((rule, i) => (
                      <li key={i}>
                        {typeof rule === 'string'
                          ? rule
                          : `${rule.id}: ${rule.description}`}
                      </li>
                    ))}
                  </ul>
                  {scanResult.matchedRules.length > 3 && (
                    <details>
                      <summary>Matched rules ({scanResult.matchedRules.length})</summary>
                      <ul>
                        {scanResult.matchedRules.map((rule, i) => (
                          <li key={i}>
                            {typeof rule === 'string'
                              ? rule
                              : `${rule.id}: ${rule.description}`}
                          </li>
                        ))}
                      </ul>
                    </details>
                  )}
                </>
              )}
            </div>
          )}

          {scanError && !loading && (
            <div className="error-box">{scanError}</div>
          )}

        </main>
      )}

      {/* ================= HOW IT WORKS PAGE ================= */}
      {view === 'works' && (
        <main className="works-view">
          <h2 className="works-title">How it Works</h2>

          <div className="flow-path">
            {[
              {
                title: "Input of Data",
                image: "https://st.depositphotos.com/1448734/3160/i/450/depositphotos_31600637-Data-entry.jpg",
                text: `The first stage begins when the user submits raw input to the system. This input can be either a
      suspicious URL or the text of an email message. The system immediately processes this information
      through a feature extraction step that breaks the input into structured data. Elements such as domain
      structure, special characters, unusual links, suspicious keywords, and formatting patterns are identified
      and recorded. By converting raw text or URLs into measurable features, the system prepares the data for
      deeper analysis in later stages.`
              },
              {
                title: "NFA/DFA PIPELINE",
                image: "https://media.istockphoto.com/id/1368750477/vector/oil-pipeline-low-poly-business-concept-finance-economy-polygonal-petrol-production-petroleum.jpg?s=612x612&w=0&k=20&c=7r5jfC_0-_DVy0wonFmuWdTTInAhjW9-s91XvLRajK4=",
                text: `After the input has been structured, the system applies principles from formal language theory
      to detect known phishing patterns. Regular expressions are used to represent suspicious patterns
      commonly found in phishing links and messages. These expressions are first interpreted through
      Non-Deterministic Finite Automata (NFA), which allows the system to explore multiple pattern paths
      simultaneously. The NFA is then converted into a Deterministic Finite Automaton (DFA) to create a
      faster and more efficient pattern matching process. This pipeline ensures that known malicious structures
      can be identified quickly and consistently.`
              },
              {
                title: "Machine Learning Classification",
                image: "https://media.istockphoto.com/id/1387900612/photo/automation-data-analytic-with-robot-and-digital-visualization-for-big-data-scientist.jpg?s=612x612&w=0&k=20&c=50maOJU6CpVC55mYnUqtff2aiaJZ7KlmMn4jNhWD_eo=",
                text: `In the final stage, the extracted features and pattern analysis results are passed to a machine learning model.
      The classifier evaluates the input using trained algorithms such as Logistic Regression or Random Forest models
      that have learned from large datasets of legitimate and phishing examples. By analyzing relationships between
      features, the model calculates the probability that the input represents a phishing attempt. The system then
      produces a final risk score and classification, providing users with a clear indication of whether the content
      is likely safe or malicious.`
              }
            ].map((step, i) => (
              <div key={i} className="work-card">
                <img src={step.image} alt={step.title} />
                <div className="card-top">
                  <span className="card-title">{step.title}</span>
                </div>
                <div className="card-body">
                  <p>{step.text}</p>
                </div>
              </div>
            ))}
          </div>
        </main>
      )}

      {/* ================= ABOUT US PAGE ================= */}
      {view === 'about' && (
        <main className="about-view">
          <div className="mission-header">
            <div className="hr-line"></div>
            <h2>Our Mission</h2>
            <div className="hr-line"></div>
          </div>

          <p className="tagline">Empowering Trustworthy AI Solutions for a Better Tomorrow.</p>

          <div className="photo-gallery">
            {teamMembers.map((member, i) => (
              <div key={i} className="photo-card">
                <img src={member.url} alt={member.name} />
                <p className="member-name">{member.name}</p>
              </div>
            ))}
            <div className="glow-line"></div>
          </div>

          <div className="values-row">
            {[
              { title: "Explainability", image: "...", text: "Our platform prioritizes transparency..." },
              { title: "Trust", image: "...", text: "Trust is achieved through a hybrid detection architecture..." },
              { title: "Ethics", image: "...", text: "The system is designed with responsible AI principles..." }
            ].map((item, i) => (
              <div key={i} className={`val-box ${item.title === "Trust" ? "focus" : ""}`} style={{ backgroundImage: `url(${item.image})` }}>
                <h3>{item.title}</h3>
                <p>{item.text}</p>
              </div>
            ))}
          </div>
        </main>
      )}
    </div>
  )
}
export default App