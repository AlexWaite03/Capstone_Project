// useScanner.jsx
import { useState } from 'react'

const API_BASE = 'https://cyberlang-phishing-detector.onrender.com'

// ---- API call ------------------------------------------------------------

async function callPredict(payload) {
  const res = await fetch(`${API_BASE}/predict`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}))
    throw new Error(detail.detail || `Request failed (${res.status})`)
  }
  return res.json()
}

// ---- Result shaping ------------------------------------------------------

function shapeResult(apiResponse, scanType) {
  const block = scanType === 'URL'
    ? apiResponse.url_prediction
    : apiResponse.email_prediction

  if (!block) {
    throw new Error('API returned no prediction for this input')
  }

  const percentage = Math.round(block.confidence * 100)
  const riskLabel =
    percentage >= 50 ? 'High Risk' :
    percentage >= 10 ? 'Medium Risk' : 'Low Risk'

  return {
    scanType,
    isPhishing: block.is_phishing,
    percentage,
    riskLabel,
    matchedRules: block.matched_rules || [],
  }
}

export async function analyzeUrl(url) {
  const data = await callPredict({ url })
  return shapeResult(data, 'URL')
}

export async function analyzeEmail({ body_text }) {
  const data = await callPredict({ email_text: body_text })
  return shapeResult(data, 'Email')
}

// ---- Hook ----------------------------------------------------------------

export function useScanner() {
  const [loading, setLoading] = useState(false)
  const [scanResult, setScanResult] = useState(null)
  const [scanError, setScanError] = useState(null)

  const analyze = async ({ scanType, inputValue }) => {
    setScanResult(null)
    setScanError(null)

    if (!inputValue.trim()) {
      setScanError('Please enter a URL or Email text before analyzing.')
      return
    }

    let payload
    if (scanType === 'URL') {
      let urlToScan = inputValue.trim()
      if (!urlToScan.match(/^https?:\/\//i)) {
        urlToScan = 'https://' + urlToScan
      }
      try { new URL(urlToScan) }
      catch {
        setScanError('Please enter a valid URL.')
        return
      }
      payload = { url: urlToScan }
    } else {
      if (inputValue.length < 10) {
        setScanError('Email text is too short.')
        return
      }
      payload = { email_text: inputValue }
    }

    
    setLoading(true)

    try {
      const apiResponse = await callPredict(payload)
      setScanResult(shapeResult(apiResponse, scanType))
    } catch (err) {
      setScanError(err.message || 'Scan failed')
      setScanResult(null)
    } finally {
      setLoading(false)
    }
  }

  const reset = () => {
    setScanResult(null)
    setScanError(null)
    setLoading(false)
  }

  return { loading, scanResult, scanError, analyze, reset }
}