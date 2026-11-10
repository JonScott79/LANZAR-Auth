import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import './AdminSupportVerification.css'

export default function AdminSupportVerification({ admin, user }) {
  const navigate = useNavigate()
  const [searchTerm, setSearchTerm] = useState('')
  const [customers, setCustomers] = useState([])
  const [selectedCustomer, setSelectedCustomer] = useState(null)
  const [loading, setLoading] = useState(false)
  const [errorMsg, setErrorMsg] = useState(null)
  const [successMsg, setSuccessMsg] = useState(null)

  // Challenge State
  const [activeChallenge, setActiveChallenge] = useState(null)
  const [otpInput, setOtpInput] = useState('')
  const [actionTaken, setActionTaken] = useState('identity_verification')
  const [ticketIdInput, setTicketIdInput] = useState('')
  const [verificationResult, setVerificationResult] = useState(null)

  const apiBaseUrl = window.location.hostname === 'localhost' ? 'http://localhost:3001' : 'https://api.tickets.lanzar.me'

  const handleSearch = async (e) => {
    e?.preventDefault()
    if (!searchTerm.trim()) return
    setLoading(true)
    setErrorMsg(null)
    setSelectedCustomer(null)
    setActiveChallenge(null)
    setVerificationResult(null)

    try {
      const idToken = await user.getIdToken()
      const res = await fetch(`${apiBaseUrl}/api/admin/support/customers?q=${encodeURIComponent(searchTerm.trim())}`, {
        headers: {
          'Authorization': `Bearer ${idToken}`
        }
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Failed to search customers.')
      setCustomers(data.customers || [])
      if (data.customers.length === 0) {
        setErrorMsg('No customers found matching that search criteria.')
      }
    } catch (err) {
      setErrorMsg(err.message)
    } finally {
      setLoading(false)
    }
  }

  const handleSendChallenge = async (customer) => {
    setLoading(true)
    setErrorMsg(null)
    setSuccessMsg(null)
    try {
      const idToken = await user.getIdToken()
      const res = await fetch(`${apiBaseUrl}/api/admin/support/challenge`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${idToken}`
        },
        body: JSON.stringify({
          customerUid: customer.uid,
          channel: 'email'
        })
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Failed to initiate verification challenge.')
      setActiveChallenge(data)
      setSuccessMsg(`One-time verification code sent to ${data.destinationMasked}. Ask the caller for the 6-digit code.`)
    } catch (err) {
      setErrorMsg(err.message)
    } finally {
      setLoading(false)
    }
  }

  const handleConfirmVerification = async (e) => {
    e.preventDefault()
    if (!activeChallenge || !otpInput.trim()) return
    setLoading(true)
    setErrorMsg(null)

    try {
      const idToken = await user.getIdToken()
      const res = await fetch(`${apiBaseUrl}/api/admin/support/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${idToken}`
        },
        body: JSON.stringify({
          challengeId: activeChallenge.challengeId,
          code: otpInput.trim(),
          ticketId: ticketIdInput.trim() || null,
          actionTaken
        })
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Verification failed.')
      setVerificationResult(data)
      setActiveChallenge(null)
      setOtpInput('')
      setSuccessMsg(`Caller successfully verified! Audit Reference: ${data.verificationId}`)
    } catch (err) {
      setErrorMsg(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="support-verif-container">
      <div className="support-header">
        <div>
          <h2 className="support-title">SUPPORT CALLER VERIFICATION</h2>
          <p className="support-subtitle">Search customer accounts, issue one-time verification challenges, and establish an immutable security audit trail.</p>
        </div>
        <div className="security-shield-badge">P0 SECURITY ENFORCED</div>
      </div>

      {/* Search Bar */}
      <form onSubmit={handleSearch} className="support-search-form">
        <input 
          type="text" 
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          placeholder="Search customer by name, email, phone, or company name..."
          className="support-search-input"
          disabled={loading}
        />
        <button type="submit" className="primary-btn search-submit-btn" disabled={loading || !searchTerm.trim()}>
          {loading ? 'SEARCHING...' : 'LOOKUP CUSTOMER'}
        </button>
      </form>

      {errorMsg && <div className="error-banner">{errorMsg}</div>}
      {successMsg && <div className="success-banner">{successMsg}</div>}

      {/* Search Results */}
      {customers.length > 0 && (
        <div className="customer-results-grid">
          {customers.map((c) => (
            <div 
              key={c.uid} 
              className={`customer-card ${selectedCustomer?.uid === c.uid ? 'selected' : ''}`}
              onClick={() => { setSelectedCustomer(c); setActiveChallenge(null); setVerificationResult(null); }}
            >
              <div className="customer-card-header">
                <span className="customer-card-name">{c.name}</span>
                <span className={`status-pill ${c.active ? 'active' : 'inactive'}`}>
                  {c.active ? 'ACTIVE' : 'INACTIVE'}
                </span>
              </div>
              <div className="customer-detail-line"><strong>Email:</strong> {c.email}</div>
              {c.phone && <div className="customer-detail-line"><strong>Phone:</strong> {c.phone}</div>}
              {c.businessName && <div className="customer-detail-line"><strong>Company:</strong> {c.businessName}</div>}
              <div className="customer-detail-line"><strong>Services:</strong> {c.services.join(', ') || 'None'}</div>
              <button 
                type="button" 
                className="select-customer-btn"
                onClick={(e) => { e.stopPropagation(); setSelectedCustomer(c); }}
              >
                SELECT FOR CALL VERIFICATION
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Selected Customer Verification Workspace */}
      {selectedCustomer && (
        <div className="verification-workspace">
          <div className="workspace-header">
            <div>
              <h3>ACTIVE CALL: {selectedCustomer.name}</h3>
              <p className="workspace-meta">
                Account ID: <code>{selectedCustomer.accountId || selectedCustomer.uid}</code> &bull; Email: <code>{selectedCustomer.email}</code>
              </p>
            </div>
            <div>
              {verificationResult?.verified ? (
                <div className="verif-status-badge verified">✓ IDENTITY VERIFIED</div>
              ) : (
                <div className="verif-status-badge unverified">⚠ UNVERIFIED CALLER</div>
              )}
            </div>
          </div>

          {!verificationResult?.verified && !activeChallenge && (
            <div className="challenge-trigger-box">
              <p>To access sensitive account tools, reset credentials, or make billing changes, initiate an out-of-band verification challenge.</p>
              <button 
                type="button" 
                className="primary-btn initiate-btn"
                onClick={() => handleSendChallenge(selectedCustomer)}
                disabled={loading}
              >
                {loading ? 'SENDING CHALLENGE...' : 'INITIATE OTP VERIFICATION CHALLENGE'}
              </button>
            </div>
          )}

          {activeChallenge && (
            <form onSubmit={handleConfirmVerification} className="challenge-verify-box">
              <div className="active-challenge-notice">
                <span>Code dispatched to <strong>{activeChallenge.destinationMasked}</strong>. Ask caller for the 6-digit code.</span>
              </div>

              <div className="form-row">
                <div className="form-col">
                  <label htmlFor="otp-input">6-DIGIT VERIFICATION CODE *</label>
                  <input 
                    id="otp-input"
                    type="text" 
                    maxLength={6}
                    value={otpInput}
                    onChange={(e) => setOtpInput(e.target.value)}
                    placeholder="e.g. 849204"
                    required
                    autoFocus
                  />
                </div>

                <div className="form-col">
                  <label htmlFor="action-select">ACTION BEING PERFORMED *</label>
                  <select 
                    id="action-select"
                    value={actionTaken}
                    onChange={(e) => setActionTaken(e.target.value)}
                  >
                    <option value="identity_verification">Standard Identity Verification</option>
                    <option value="password_access_reset">Password / Access Reset</option>
                    <option value="service_entitlement_change">Service Entitlement Change</option>
                    <option value="billing_account_update">Billing & Payment Update</option>
                    <option value="infrastructure_config_change">Infrastructure & DNS Modification</option>
                  </select>
                </div>

                <div className="form-col">
                  <label htmlFor="ticket-input">RELATED TICKET ID (OPTIONAL)</label>
                  <input 
                    id="ticket-input"
                    type="text" 
                    value={ticketIdInput}
                    onChange={(e) => setTicketIdInput(e.target.value)}
                    placeholder="e.g. tkt_17931298"
                  />
                </div>
              </div>

              <button type="submit" className="primary-btn confirm-verify-btn" disabled={loading || otpInput.length < 6}>
                {loading ? 'VERIFYING...' : 'CONFIRM OTP & AUTHORIZE CALLER'}
              </button>
            </form>
          )}

          {verificationResult?.verified && (
            <div className="verified-success-box">
              <h4>IDENTITY VERIFICATION AUDIT LOGGED</h4>
              <p>Caller identity confirmed. Audit record created with ID: <code>{verificationResult.verificationId}</code></p>
              <div className="authorized-actions-bar">
                <button type="button" className="action-pill-btn" onClick={() => navigate('/admin/terminal', { state: { customerName: selectedCustomer.name || selectedCustomer.companyName, customerEmail: selectedCustomer.email, customerPhone: selectedCustomer.phone } })}>💳 Take Payment (Virtual Terminal)</button>
                <button type="button" className="action-pill-btn" onClick={() => alert('Password reset link sent to registered email.')}>Send Password Reset</button>
                <button type="button" className="action-pill-btn" onClick={() => alert('Routing to Ticket System...')}>Open Support Ticket</button>
                <button type="button" className="action-pill-btn" onClick={() => alert('Viewing billing invoice history...')}>Inspect Invoices</button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
