import { useState } from 'react'
import './App.css'

function App() {
  const [view, setView] = useState('scanner'); 
  const [scanType, setScanType] = useState('URL') // 'URL' or 'Email'
  const [showInfo, setShowInfo] = useState(false)

  const teamPhotos = [
    "https://images.pexels.com/photos/415829/pexels-photo-415829.jpeg?auto=compress&cs=tinysrgb&w=200",
    "https://images.pexels.com/photos/220453/pexels-photo-220453.jpeg?auto=compress&cs=tinysrgb&w=200",
    "https://images.pexels.com/photos/1181682/pexels-photo-1181682.jpeg?auto=compress&cs=tinysrgb&w=200",
    "https://images.pexels.com/photos/2379004/pexels-photo-2379004.jpeg?auto=compress&cs=tinysrgb&w=200",
    "https://images.pexels.com/photos/1222271/pexels-photo-1222271.jpeg?auto=compress&cs=tinysrgb&w=200"
  ];

  return (
    <div className="container">
      {/* Universal Navbar */}
      <nav className="navbar">
        <div className="logo-section">
          <span className="logo-icon">@</span>
          <span className="logo-text">CyberLang Analytics</span>
        </div>
        <div className="nav-links">
          <button className={view === 'scanner' ? 'nav-item active' : 'nav-item'} onClick={() => setView('scanner')}>Scanner</button>
          <button className={view === 'works' ? 'nav-item active' : 'nav-item'} onClick={() => setView('works')}>How it Works</button>
          <button className={view === 'about' ? 'nav-item active' : 'nav-item'} onClick={() => setView('about')}>About Us</button>
        </div>
      </nav>

      {/* 1. Scanner Page */}
      {view === 'scanner' && (
        <main className="scanner-hero">
          <h1>Hybrid Phishing & Scam Detection</h1>
          <p className="subtitle">Analyze URLs & Email Text with Automata & Machine Learning</p>

          {/* Sliding Toggle */}
          <div className="slider-box">
            <div className={`slider-active-overlay ${scanType === 'Email' ? 'right' : 'left'}`}></div>
            <button className="slider-btn" onClick={() => setScanType('URL')}>URL Scan</button>
            <button className="slider-btn" onClick={() => setScanType('Email')}>Email Text Scan</button>
          </div>

          <div className="input-row">
            <div className="input-container">
              {scanType === 'URL' ? (
                <input type="text" className="scan-field" placeholder="https://suspisious-bank-login.com/" />
              ) : (
                <textarea className="scan-field email-field" placeholder="Paste email text here..." rows="6" />
              )}
            </div>
            
            <div className="info-anchor">
              <div className="info-btn" onClick={() => setShowInfo(!showInfo)}>i</div>
              {showInfo && (
                <div className="info-message">
                  Our AI = Formal Languages check for known malicious patterns
                </div>
              )}
            </div>
          </div>

          <button className="big-analyze-btn">Analyze</button>
        </main>
      )}
{/* 2. How it Works Page */}
{view === 'works' && (
  <main className="works-view">
    <h2 className="works-title">How it Works</h2>

    <div className="flow-path">
      {[
        {
          title: "Input of Data",
          text: [
  "The initial phase of the system begins when a user submits raw data, such as a specific URL or the body of an email, through the web-based scanner interface.",

  "This input undergoes a rigorous Feature Extraction process where the system identifies and isolates key indicators of malicious intent.",

  "These features are categorized into lexical elements (like suspicious keywords), structural components (such as mismatched hyperlinked domains), and statistical signatures (like the frequency of urgent or threatening language).",

  "By breaking down the raw input into these standardized data points, the system prepares a detailed profile that can be accurately parsed by the subsequent layers of the hybrid detection engine."
]
        },
        {
          title: "NFA/DFA PIPELINE",
          text: ["The second stage utilizes Formal Language Theory to perform a deep-level lexical analysis of the extracted features",
             "through a multi-step Automata Pipeline. Initially, complex Regular Expressions (Regex) are used to define known malicious patterns",
              "which are then converted into Non-deterministic Finite Automata (NFA) to account for various pattern possibilities.",
              "These NFAs are systematically transformed into Deterministic Finite Automata (DFA), creating a mathematically precise state-machine",
               "that processes the input string-by-string. This ensures that any hard-coded phishing patterns or specific character sequences are identified with absolute certainty",
                "providing a transparent and explainable trail of evidence that identifies exactly which state transition triggered a red flag.",
  ]
        },
        {
          title: "MACHINE LEARNING CLASSIFICATION",
          text: [" the final stage, the metadata generated by the Automata pipeline is",
                "integrated into a Machine Learning Classifier to handle the nuanced, statistical side of phishing detection.",
                "Using models such as Random Forest and Logistic Regression, the system compares the current input's features" ,
                "against a vast knowledge base derived from PhishTank and Kaggle datasets. This hybrid approach allows the AI",
                "to calculate a final risk probability based on historical trends and complex data relationships that a static",
                "DFA might miss. The result is a highly accurate classification that bridges the gap between rigid mathematical",
                "logic and flexible statistical analysis, ultimately delivering the explanatory feedback that justifies the final",
                "Phishing or Legitimate verdict to the user.",
    ]      
        },
        

      ].map((step, i, arr) => (
        <div key={i} className="flow-step">
          <div className="work-card">
            <div className="card-top">
              <span className="card-title">{step.title}</span>
              <div className="mini-i">i</div>
            </div>

            <div className="card-body">
              <p>{step.text}</p>
            </div>
          </div>

          {i < arr.length - 1 && (
            <div className="flow-arrow">↓</div>
          )}
        </div>
      ))}
    </div>
  </main>
)}

      {/* 3. About Us Page */}
      {view === 'about' && (
        <main className="about-view">
          <div className="mission-header">
            <div className="hr-line"></div>
            <h2>Our Mission</h2>
            <div className="hr-line"></div>
          </div>
          <p className="tagline">Empowering Trustworthy AI Solutions for a Better Tomorrow.</p>
          
          <div className="photo-gallery">
            {teamPhotos.map((url, i) => (
              <div key={i} className="photo-card"><img src={url} alt="team" /></div>
            ))}
            <div className="glow-line"></div>
          </div>

          <div className="values-row">
            <div className="val-box"><h3>Explainability</h3><p>We make AI understandable and transparent.</p></div>
            <div className="val-box focus"><h3>Trust</h3><p>Building confidence in every AI solution.</p></div>
            <div className="val-box"><h3>Ethics</h3><p>Committed to responsible and fair AI practices.</p></div>
          </div>
        </main>
      )}
    </div>
  )
}

export default App