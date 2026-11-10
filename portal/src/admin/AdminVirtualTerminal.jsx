import { useState, useEffect } from 'react'
import { useLocation } from 'react-router-dom'
import './AdminVirtualTerminal.css'

export default function AdminVirtualTerminal({ admin, user }) {
  const location = useLocation()

  // Customer / Caller Info
  const [callerName, setCallerName] = useState('')
  const [callerEmail, setCallerEmail] = useState('')
  const [callerPhone, setCallerPhone] = useState('')

  // Selected Service
  const [selectedPreset, setSelectedPreset] = useState('homeowner')
  const [hourlyCount, setHourlyCount] = useState(1)
  const [customAmount, setCustomAmount] = useState('')
  const [customDesc, setCustomDesc] = useState('')

  // Terminal Mode: 'card' (Charge card over phone) vs 'link' (Generate / Send payment link)
  const [mode, setMode] = useState('card')

  // Card Details
  const [cardNumber, setCardNumber] = useState('')
  const [expMonth, setExpMonth] = useState('')
  const [expYear, setExpYear] = useState('')
  const [cvc, setCvc] = useState('')
  const [postalCode, setPostalCode] = useState('')

  // Transaction Status
  const [loading, setLoading] = useState(false)
  const [errorMsg, setErrorMsg] = useState(null)
  const [successData, setSuccessData] = useState(null)
  const [generatedLink, setGeneratedLink] = useState(null)
  const [copiedLink, setCopiedLink] = useState(false)

  const apiBaseUrl = window.location.hostname === 'localhost' ? 'http://localhost:3001' : 'https://api.tickets.lanzar.me'

  // Pre-fill from navigation state (e.g. from Triage Guide or Caller Verification)
  useEffect(() => {
    if (location.state?.preset) {
      setSelectedPreset(location.state.preset)
    }
    if (location.state?.customerName) {
      setCallerName(location.state.customerName)
    }
    if (location.state?.customerEmail) {
      setCallerEmail(location.state.customerEmail)
    }
    if (location.state?.customerPhone) {
      setCallerPhone(location.state.customerPhone)
    }
    if (location.state?.customDesc) {
      setCustomDesc(location.state.customDesc)
    }
  }, [location.state])

  // Presets definition
  const PRESETS = {
    homeowner: {
      name: 'Managed IT - Homeowner Plan',
      amount: 4900,
      displayPrice: '$49.00 / month',
      type: 'subscription',
      directLink: 'https://buy.stripe.com/14A5kx8RO5BEdcga083oA01'
    },
    business: {
      name: 'Managed IT - Small Business Plan',
      amount: 25000,
      displayPrice: '$250.00 / month',
      type: 'subscription',
      directLink: 'https://buy.stripe.com/aFa4gtgkg4xAfkofks3oA04'
    },
    admin: {
      name: 'Managed IT - Full Admin Plan',
      amount: 50000,
      displayPrice: '$500.00 / month',
      type: 'subscription',
      directLink: 'https://buy.stripe.com/dRmeV7d842psdcgego3oA05'
    },
    hourly: {
      name: `Hourly Remote/On-Site IT Support (${hourlyCount} hr${hourlyCount > 1 ? 's' : ''})`,
      amount: hourlyCount * 15000,
      displayPrice: `$${hourlyCount * 150}.00 ($150/hr)`,
      type: 'one_time'
    },
    tuneup: {
      name: 'Deep PC / Mac Tune-Up & Malware Removal',
      amount: 10000,
      displayPrice: '$100.00 flat',
      type: 'one_time'
    },
    setup: {
      name: 'New Computer Setup & Data Migration',
      amount: 15000,
      displayPrice: '$150.00 flat',
      type: 'one_time'
    },
    network: {
      name: 'Home Network & Wi-Fi Optimization',
      amount: 15000,
      displayPrice: '$150.00 flat',
      type: 'one_time'
    },
    custom: {
      name: customDesc || 'Custom IT Diagnostic Service',
      amount: Math.round(parseFloat(customAmount || '0') * 100),
      displayPrice: customAmount ? `$${parseFloat(customAmount).toFixed(2)}` : '$0.00',
      type: 'one_time'
    }
  }

  const activePreset = PRESETS[selectedPreset] || PRESETS.homeowner
  const chargeAmountCents = activePreset.amount

  // Format Card Number input with spaces
  const handleCardNumberChange = (e) => {
    const raw = e.target.value.replace(/\D/g, '').slice(0, 16)
    const formatted = raw.replace(/(\d{4})(?=\d)/g, '$1 ')
    setCardNumber(formatted)
  }

  // Charge Card Over Phone Handler
  const handleChargeCard = async (e) => {
    e.preventDefault()
    setErrorMsg(null)
    setSuccessData(null)

    if (!callerName.trim() || !callerEmail.trim()) {
      setErrorMsg('Customer name and email address are required for invoicing.')
      return
    }

    if (!cardNumber || !expMonth || !expYear || !cvc) {
      setErrorMsg('Complete card details (number, exp, CVC) are required.')
      return
    }

    if (chargeAmountCents < 50) {
      setErrorMsg('Minimum charge amount is $0.50.')
      return
    }

    setLoading(true)

    try {
      const idToken = await user.getIdToken()
      const res = await fetch(`${apiBaseUrl}/api/admin/billing/charge-card`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${idToken}`
        },
        body: JSON.stringify({
          customerName: callerName.trim(),
          customerEmail: callerEmail.trim(),
          customerPhone: callerPhone.trim(),
          amount: chargeAmountCents,
          description: activePreset.name,
          serviceId: selectedPreset,
          cardNumber: cardNumber.replace(/\s+/g, ''),
          expMonth: parseInt(expMonth, 10),
          expYear: parseInt(expYear, 10),
          cvc: cvc.trim(),
          postalCode: postalCode.trim()
        })
      })

      const data = await res.json()
      if (!res.ok) {
        throw new Error(data.error || 'Failed to authorize and process card.')
      }

      setSuccessData(data)
      // Clear sensitive card numbers on success
      setCardNumber('')
      setExpMonth('')
      setExpYear('')
      setCvc('')
      setPostalCode('')
    } catch (err) {
      setErrorMsg(err.message)
    } finally {
      setLoading(false)
    }
  }

  // Generate Payment Link Handler
  const handleGenerateLink = async () => {
    setErrorMsg(null)
    setGeneratedLink(null)
    setCopiedLink(false)

    // For standard presets with existing direct links, use them immediately
    if (activePreset.directLink) {
      setGeneratedLink(activePreset.directLink)
      return
    }

    setLoading(true)
    try {
      const idToken = await user.getIdToken()
      const res = await fetch(`${apiBaseUrl}/api/admin/billing/generate-link`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${idToken}`
        },
        body: JSON.stringify({
          name: activePreset.name,
          amount: chargeAmountCents,
          description: `LANZAR IT Dispatch: ${activePreset.name}`
        })
      })

      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Failed to create payment link.')
      setGeneratedLink(data.url)
    } catch (err) {
      setErrorMsg(err.message)
    } finally {
      setLoading(false)
    }
  }

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text)
    setCopiedLink(true)
    setTimeout(() => setCopiedLink(false), 2500)
  }

  return (
    <div className="terminal-container">
      
      {/* Page Header */}
      <div className="terminal-header">
        <div>
          <span className="terminal-tag">💳 SECURE DISPATCH DESK</span>
          <h1 className="terminal-title">PHONE VIRTUAL TERMINAL</h1>
          <p className="terminal-sub">
            Process caller credit cards over the phone or generate instant Stripe payment links during live support triage.
          </p>
        </div>
        <div className="terminal-status-badge">
          <span className="status-dot"></span> STRIPE LIVE CONNECTED
        </div>
      </div>

      {errorMsg && (
        <div className="terminal-alert alert-error">
          <span>⚠️</span> {errorMsg}
        </div>
      )}

      {successData && (
        <div className="terminal-alert alert-success">
          <div>
            <strong>✓ PAYMENT AUTHORIZED &amp; PROCESSED!</strong>
            <p style={{ margin: '4px 0 0', fontSize: '0.9rem' }}>
              Charged ${(chargeAmountCents / 100).toFixed(2)} to {callerEmail}. Receipt sent automatically.
            </p>
            {successData.receiptUrl && (
              <a href={successData.receiptUrl} target="_blank" rel="noopener noreferrer" style={{ color: '#0369a1', fontWeight: 'bold', fontSize: '0.85rem' }}>
                View Stripe Customer Receipt ↗
              </a>
            )}
          </div>
        </div>
      )}

      <div className="terminal-grid">
        
        {/* Left Column: Caller & Service Configuration */}
        <div className="terminal-card">
          <h2 className="card-section-title">1. CALLER INFORMATION</h2>
          
          <div className="form-group">
            <label className="form-label">Customer / Cardholder Name *</label>
            <input 
              type="text" 
              className="terminal-input" 
              placeholder="e.g. Eleanor Vance" 
              value={callerName} 
              onChange={(e) => setCallerName(e.target.value)} 
            />
          </div>

          <div className="form-row">
            <div className="form-group">
              <label className="form-label">Email Address (For Invoicing) *</label>
              <input 
                type="email" 
                className="terminal-input" 
                placeholder="caller@example.com" 
                value={callerEmail} 
                onChange={(e) => setCallerEmail(e.target.value)} 
              />
            </div>
            <div className="form-group">
              <label className="form-label">Phone Number</label>
              <input 
                type="tel" 
                className="terminal-input" 
                placeholder="(508) 555-0199" 
                value={callerPhone} 
                onChange={(e) => setCallerPhone(e.target.value)} 
              />
            </div>
          </div>

          <h2 className="card-section-title" style={{ marginTop: '1.5rem' }}>2. SELECT SERVICE OR RATE</h2>
          
          <div className="preset-selector">
            <button 
              type="button" 
              className={`preset-btn ${selectedPreset === 'homeowner' ? 'active' : ''}`}
              onClick={() => setSelectedPreset('homeowner')}
            >
              <div className="preset-name">🏠 Homeowner Plan</div>
              <div className="preset-price">$49 / mo</div>
            </button>

            <button 
              type="button" 
              className={`preset-btn ${selectedPreset === 'business' ? 'active' : ''}`}
              onClick={() => setSelectedPreset('business')}
            >
              <div className="preset-name">🏢 Small Business</div>
              <div className="preset-price">$250 / mo</div>
            </button>

            <button 
              type="button" 
              className={`preset-btn ${selectedPreset === 'admin' ? 'active' : ''}`}
              onClick={() => setSelectedPreset('admin')}
            >
              <div className="preset-name">🛡️ Full Admin Plan</div>
              <div className="preset-price">$500 / mo</div>
            </button>

            <button 
              type="button" 
              className={`preset-btn ${selectedPreset === 'hourly' ? 'active' : ''}`}
              onClick={() => setSelectedPreset('hourly')}
            >
              <div className="preset-name">⏱️ Hourly Support</div>
              <div className="preset-price">$150 / hr</div>
            </button>

            <button 
              type="button" 
              className={`preset-btn ${selectedPreset === 'tuneup' ? 'active' : ''}`}
              onClick={() => setSelectedPreset('tuneup')}
            >
              <div className="preset-name">⚡ Tune-Up / Malware</div>
              <div className="preset-price">$100 flat</div>
            </button>

            <button 
              type="button" 
              className={`preset-btn ${selectedPreset === 'setup' ? 'active' : ''}`}
              onClick={() => setSelectedPreset('setup')}
            >
              <div className="preset-name">💻 PC/Mac Setup</div>
              <div className="preset-price">$150 flat</div>
            </button>

            <button 
              type="button" 
              className={`preset-btn ${selectedPreset === 'network' ? 'active' : ''}`}
              onClick={() => setSelectedPreset('network')}
            >
              <div className="preset-name">📶 Wi-Fi Overhaul</div>
              <div className="preset-price">$150 flat</div>
            </button>

            <button 
              type="button" 
              className={`preset-btn ${selectedPreset === 'custom' ? 'active' : ''}`}
              onClick={() => setSelectedPreset('custom')}
            >
              <div className="preset-name">✏️ Custom Amount</div>
              <div className="preset-price">Custom</div>
            </button>
          </div>

          {/* Conditional Sub-options */}
          {selectedPreset === 'hourly' && (
            <div className="sub-options-box">
              <label className="form-label">Support Hours to Bill:</label>
              <div className="quantity-controls">
                <button type="button" className="qty-btn" onClick={() => setHourlyCount(Math.max(1, hourlyCount - 1))}>-</button>
                <span className="qty-display">{hourlyCount} Hour{hourlyCount > 1 ? 's' : ''}</span>
                <button type="button" className="qty-btn" onClick={() => setHourlyCount(hourlyCount + 1)}>+</button>
                <span style={{ marginLeft: 'auto', fontWeight: 'bold', color: '#22c55e' }}>
                  Total: ${(hourlyCount * 150).toFixed(2)}
                </span>
              </div>
            </div>
          )}

          {selectedPreset === 'custom' && (
            <div className="sub-options-box">
              <div className="form-row">
                <div className="form-group">
                  <label className="form-label">Charge Amount ($ USD) *</label>
                  <input 
                    type="number" 
                    step="0.01" 
                    min="1" 
                    className="terminal-input" 
                    placeholder="e.g. 75.00" 
                    value={customAmount} 
                    onChange={(e) => setCustomAmount(e.target.value)} 
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Invoice / Work Reason *</label>
                  <input 
                    type="text" 
                    className="terminal-input" 
                    placeholder="e.g. Emergency Router Replacement" 
                    value={customDesc} 
                    onChange={(e) => setCustomDesc(e.target.value)} 
                  />
                </div>
              </div>
            </div>
          )}

          {/* Charge Summary Dock */}
          <div className="charge-summary-dock">
            <div>
              <span className="summary-label">LINE ITEM:</span>
              <strong className="summary-service-name">{activePreset.name}</strong>
            </div>
            <div style={{ textAlign: 'right' }}>
              <span className="summary-label">TOTAL AUTHORIZATION:</span>
              <div className="summary-amount">{activePreset.displayPrice}</div>
            </div>
          </div>

        </div>

        {/* Right Column: Payment Execution Deck */}
        <div className="terminal-card">
          <div className="mode-toggle">
            <button 
              type="button" 
              className={`mode-btn ${mode === 'card' ? 'active' : ''}`}
              onClick={() => setMode('card')}
            >
              💳 Take Card Over Phone
            </button>
            <button 
              type="button" 
              className={`mode-btn ${mode === 'link' ? 'active' : ''}`}
              onClick={() => { setMode('link'); handleGenerateLink(); }}
            >
              🔗 Generate Payment Link
            </button>
          </div>

          {mode === 'card' ? (
            <form onSubmit={handleChargeCard} className="card-form">
              <div className="pci-notice">
                🔒 <strong>PCI DSS Compliant:</strong> Card numbers are tokenized directly via Stripe over encrypted TLS 1.3. Numbers are never written to disk or plain logs.
              </div>

              <div className="form-group">
                <label className="form-label">Card Number *</label>
                <div className="input-with-icon">
                  <input 
                    type="text" 
                    className="terminal-input card-input" 
                    placeholder="4000 1234 5678 9010" 
                    value={cardNumber} 
                    onChange={handleCardNumberChange} 
                    maxLength="19"
                    required 
                  />
                  <span className="input-icon">💳</span>
                </div>
              </div>

              <div className="form-row three-col">
                <div className="form-group">
                  <label className="form-label">Exp Month (MM) *</label>
                  <input 
                    type="text" 
                    className="terminal-input" 
                    placeholder="MM" 
                    maxLength="2" 
                    value={expMonth} 
                    onChange={(e) => setExpMonth(e.target.value.replace(/\D/g, ''))} 
                    required 
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Exp Year (YYYY) *</label>
                  <input 
                    type="text" 
                    className="terminal-input" 
                    placeholder="YYYY" 
                    maxLength="4" 
                    value={expYear} 
                    onChange={(e) => setExpYear(e.target.value.replace(/\D/g, ''))} 
                    required 
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">CVC *</label>
                  <input 
                    type="password" 
                    className="terminal-input" 
                    placeholder="CVC" 
                    maxLength="4" 
                    value={cvc} 
                    onChange={(e) => setCvc(e.target.value.replace(/\D/g, ''))} 
                    required 
                  />
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">Billing Zip / Postal Code</label>
                <input 
                  type="text" 
                  className="terminal-input" 
                  placeholder="01752" 
                  maxLength="10" 
                  value={postalCode} 
                  onChange={(e) => setPostalCode(e.target.value)} 
                />
              </div>

              <button 
                type="submit" 
                className="btn-charge-now" 
                disabled={loading || chargeAmountCents < 50}
              >
                {loading ? 'PROCESSING SECURE STRIPE CHARGE...' : `CHARGE ${activePreset.displayPrice} OVER PHONE ↗`}
              </button>
            </form>
          ) : (
            <div className="link-mode-box">
              <p style={{ fontSize: '0.92rem', color: '#475569', lineHeight: 1.5, marginBottom: '1.25rem' }}>
                Generate a live Stripe-hosted checkout link to read out or email to the customer while on the phone:
              </p>

              {loading ? (
                <div style={{ textAlign: 'center', padding: '2rem', color: '#64748b' }}>
                  Generating secure Stripe link...
                </div>
              ) : generatedLink ? (
                <div>
                  <div className="link-display-box">
                    <input 
                      type="text" 
                      className="link-input-field" 
                      value={generatedLink} 
                      readOnly 
                    />
                    <button 
                      type="button" 
                      className="btn-copy-link" 
                      onClick={() => copyToClipboard(generatedLink)}
                    >
                      {copiedLink ? 'COPIED!' : 'COPY'}
                    </button>
                  </div>

                  <div style={{ display: 'flex', gap: '10px', marginTop: '1rem' }}>
                    <a 
                      href={generatedLink} 
                      target="_blank" 
                      rel="noopener noreferrer" 
                      className="btn-secondary"
                      style={{ textDecoration: 'none', textAlign: 'center', flex: 1 }}
                    >
                      Open Link in New Tab ↗
                    </a>
                    {callerEmail && (
                      <a 
                        href={`mailto:${callerEmail}?subject=LANZAR IT Service Checkout Link&body=Hello ${callerName || 'there'},%0D%0A%0D%0APlease find your secure checkout link for ${encodeURIComponent(activePreset.name)} here:%0D%0A${encodeURIComponent(generatedLink)}%0D%0A%0D%0AThank you,%0D%0ALANZAR Support`}
                        className="btn-secondary"
                        style={{ textDecoration: 'none', textAlign: 'center', flex: 1 }}
                      >
                        Email to Caller ✉️
                      </a>
                    )}
                  </div>
                </div>
              ) : (
                <button type="button" className="btn-charge-now" onClick={handleGenerateLink}>
                  GENERATE PAYMENT LINK ↗
                </button>
              )}
            </div>
          )}

        </div>

      </div>

    </div>
  )
}
