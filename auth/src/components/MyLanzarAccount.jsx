import { useState, useEffect } from 'react'
import { signOutUser } from '../firebase/auth.js'
import { getAuthApiUrl } from '../config/env.js'
import './MyLanzarAccount.css'

export default function MyLanzarAccount({ user, onClose = null }) {
  const [activeTab, setActiveTab] = useState('overview')
  const [loading, setLoading] = useState(true)
  const [profile, setProfile] = useState(null)
  const [sessions, setSessions] = useState([])
  const [mfaStatus, setMfaStatus] = useState(null)
  const [msg, setMsg] = useState({ text: '', type: '' })

  // Profile Form State
  const [displayName, setDisplayName] = useState('')
  const [bio, setBio] = useState('')
  const [avatarUrl, setAvatarUrl] = useState('')
  const [savingProfile, setSavingProfile] = useState(false)

  // TOTP MFA Form State (Universal RFC 6238)
  const [totpSetup, setTotpSetup] = useState(null) // { secret, otpauthUrl }
  const [totpCode, setTotpCode] = useState('')
  const [recoveryCodes, setRecoveryCodes] = useState([])
  const [totpLoading, setTotpLoading] = useState(false)

  // Phone Verification Form State
  const [phoneNumber, setPhoneNumber] = useState('')
  const [phoneCode, setPhoneCode] = useState('')
  const [otpSent, setOtpSent] = useState(false)
  const [phoneLoading, setPhoneLoading] = useState(false)

  // Account Erasure State
  const [showDeleteModal, setShowDeleteModal] = useState(false)
  const [deleteConfirmationInput, setDeleteConfirmationInput] = useState('')
  const [deletingAccount, setDeletingAccount] = useState(false)

  // The Dispatch Newsletter State (Amendment #003)
  const [dispatchSubscribed, setDispatchSubscribed] = useState(false)

  const authBackendUrl = getAuthApiUrl()

  const notify = (text, type = 'info') => {
    setMsg({ text, type })
    setTimeout(() => setMsg({ text: '', type: '' }), 6000)
  }

  // Load complete profile and sessions
  const loadAccountData = async () => {
    if (!user) return
    setLoading(true)
    try {
      const idToken = await user.getIdToken(true)

      // 1. Fetch Profile
      const profRes = await fetch(`${authBackendUrl}/api/id/profile`, {
        headers: { 'Authorization': `Bearer ${idToken}` }
      })
      if (profRes.ok) {
        const profData = await profRes.json()
        setProfile(profData)
        setDisplayName(profData.displayName || '')
        setBio(profData.bio || '')
        setAvatarUrl(profData.avatarUrl || '')
      }

      // 2. Fetch Sessions
      const sessRes = await fetch(`${authBackendUrl}/api/id/sessions`, {
        headers: { 'Authorization': `Bearer ${idToken}` }
      })
      if (sessRes.ok) {
        const sessData = await sessRes.json()
        setSessions(sessData.sessions || [])
      }

      // 3. Fetch MFA Status
      const mfaRes = await fetch(`${authBackendUrl}/mfa/status`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken })
      })
      if (mfaRes.ok) {
        const mfaData = await mfaRes.json()
        setMfaStatus(mfaData)
      }

      // 4. Fetch The Dispatch Newsletter Status (Amendment #003)
      const dispatchRes = await fetch(`${authBackendUrl}/api/id/dispatch/status`, {
        headers: { 'Authorization': `Bearer ${idToken}` }
      })
      if (dispatchRes.ok) {
        const dispatchData = await dispatchRes.json()
        setDispatchSubscribed(Boolean(dispatchData.subscribed))
      }
    } catch (err) {
      console.error('[MY LANZAR ERROR] Failed to load account:', err)
      notify('Failed to load profile details from server.', 'error')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadAccountData()
  }, [user])

  // Profile Save
  const handleSaveProfile = async (e) => {
    e.preventDefault()
    setSavingProfile(true)
    try {
      const idToken = await user.getIdToken()
      const res = await fetch(`${authBackendUrl}/api/id/profile`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${idToken}`
        },
        body: JSON.stringify({ displayName, bio, avatarUrl })
      })
      if (!res.ok) throw new Error('Failed to update profile')
      const updated = await res.json()
      setProfile(updated)
      notify('Profile updated successfully!', 'success')
    } catch (err) {
      notify(err.message, 'error')
    } finally {
      setSavingProfile(false)
    }
  }

  // Session Revoke (Individual)
  const handleRevokeSession = async (sessionId) => {
    try {
      const idToken = await user.getIdToken()
      const res = await fetch(`${authBackendUrl}/api/id/sessions/${sessionId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${idToken}` }
      })
      if (!res.ok) throw new Error('Failed to revoke session')
      setSessions(prev => prev.filter(s => s.sessionId !== sessionId))
      notify('Device session successfully revoked.', 'success')
    } catch (err) {
      notify(err.message, 'error')
    }
  }

  // Global Session Revocation ("Sign Out Everywhere")
  const handleRevokeAllSessions = async () => {
    if (!window.confirm('Are you sure you want to sign out everywhere? All active sessions across all devices will be terminated.')) {
      return
    }
    try {
      const idToken = await user.getIdToken()
      const res = await fetch(`${authBackendUrl}/api/id/sessions/revoke-all`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${idToken}` }
      })
      if (!res.ok) throw new Error('Failed to revoke sessions globally')
      notify('All sessions globally invalidated. Signing out...', 'success')
      setTimeout(() => signOutUser(), 1500)
    } catch (err) {
      notify(err.message, 'error')
    }
  }

  // TOTP MFA Setup (Universal Microsoft / Google Authenticator)
  const handleStartTotp = async () => {
    setTotpLoading(true)
    try {
      const idToken = await user.getIdToken()
      const res = await fetch(`${authBackendUrl}/mfa/totp/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken })
      })
      if (!res.ok) throw new Error('Failed to initiate TOTP setup')
      const data = await res.json()
      setTotpSetup(data)
    } catch (err) {
      notify(err.message, 'error')
    } finally {
      setTotpLoading(false)
    }
  }

  const handleEnableTotp = async (e) => {
    e.preventDefault()
    setTotpLoading(true)
    try {
      const idToken = await user.getIdToken()
      const res = await fetch(`${authBackendUrl}/mfa/totp/enable`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken, code: totpCode })
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error_description || 'Invalid verification code')
      setRecoveryCodes(data.recoveryCodes || [])
      setTotpSetup(null)
      setTotpCode('')
      notify('Authenticator MFA enabled successfully! Save your recovery codes.', 'success')
      loadAccountData()
    } catch (err) {
      notify(err.message, 'error')
    } finally {
      setTotpLoading(false)
    }
  }

  // Phone Verification Handlers
  const handleSendPhoneOtp = async (e) => {
    e.preventDefault()
    setPhoneLoading(true)
    try {
      const idToken = await user.getIdToken()
      const res = await fetch(`${authBackendUrl}/api/id/phone/send-otp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${idToken}`
        },
        body: JSON.stringify({ phoneNumber })
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error_description || 'Failed to dispatch phone code')
      setOtpSent(true)
      notify(`Verification code dispatched to ${data.phoneNumber}.`, 'info')
    } catch (err) {
      notify(err.message, 'error')
    } finally {
      setPhoneLoading(false)
    }
  }

  const handleVerifyPhoneOtp = async (e) => {
    e.preventDefault()
    setPhoneLoading(true)
    try {
      const idToken = await user.getIdToken()
      const res = await fetch(`${authBackendUrl}/api/id/phone/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${idToken}`
        },
        body: JSON.stringify({ phoneNumber, code: phoneCode })
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error_description || 'Invalid phone code')
      setOtpSent(false)
      setPhoneCode('')
      notify('Phone number verified successfully!', 'success')
      loadAccountData()
    } catch (err) {
      notify(err.message, 'error')
    } finally {
      setPhoneLoading(false)
    }
  }

  // Password Recovery Trigger
  const handleTriggerPasswordReset = async () => {
    try {
      const res = await fetch(`${authBackendUrl}/password/forgot`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: profile?.email || user.email })
      })
      if (!res.ok) throw new Error('Failed to send reset link')
      notify('Password reset email dispatched to your inbox.', 'info')
    } catch (err) {
      notify(err.message, 'error')
    }
  }

  // The Dispatch Newsletter Handlers (Amendment #003)
  const handleSubscribeDispatch = async () => {
    try {
      const idToken = await user.getIdToken()
      const res = await fetch(`${authBackendUrl}/api/id/dispatch/subscribe`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${idToken}` }
      })
      if (!res.ok) throw new Error('Failed to subscribe to The Dispatch')
      setDispatchSubscribed(true)
      notify('Subscribed to The Dispatch! Welcome to the network.', 'success')
    } catch (err) {
      notify(err.message, 'error')
    }
  }

  const handleUnsubscribeDispatch = async () => {
    try {
      const idToken = await user.getIdToken()
      const res = await fetch(`${authBackendUrl}/api/id/dispatch/unsubscribe`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${idToken}` }
      })
      if (!res.ok) throw new Error('Failed to unsubscribe from The Dispatch')
      setDispatchSubscribed(false)
      notify('Unsubscribed from The Dispatch.', 'info')
    } catch (err) {
      notify(err.message, 'error')
    }
  }

  // Data Export
  const handleExportData = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(profile, null, 2))
    const downloadAnchor = document.createElement('a')
    downloadAnchor.setAttribute('href', dataStr)
    downloadAnchor.setAttribute('download', `lanzar_id_profile_${user.uid}.json`)
    document.body.appendChild(downloadAnchor)
    downloadAnchor.click()
    downloadAnchor.remove()
  }

  // Account Erasure (GDPR / CCPA)
  const handleExecuteAccountErasure = async () => {
    if (deleteConfirmationInput !== 'DELETE') {
      notify('Please type DELETE to confirm.', 'error')
      return
    }
    setDeletingAccount(true)
    try {
      const idToken = await user.getIdToken()
      const res = await fetch(`${authBackendUrl}/api/id/account`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${idToken}` }
      })
      if (!res.ok) throw new Error('Failed to erase account')
      alert('Your LANZAR ID and all associated records have been permanently erased.')
      signOutUser()
    } catch (err) {
      notify(err.message, 'error')
      setDeletingAccount(false)
    }
  }

  if (loading) {
    return (
      <div className="my-lanzar-loading">
        <div className="lanzar-spinner"></div>
        <p>Synchronizing with LANZAR ID Core...</p>
      </div>
    )
  }

  const badges = profile?.derivedBadges || []

  return (
    <div className="my-lanzar-container">
      {/* Top Telemetry Header */}
      <header className="my-lanzar-header">
        <div className="lanzar-id-brand">
          <div className="lanzar-id-orb"></div>
          <div>
            <h2 className="lanzar-id-title">MY LANZAR</h2>
            <span className="lanzar-id-sub">UNIFIED IDENTITY &amp; ACCOUNT MANAGEMENT</span>
          </div>
        </div>
        <div className="header-actions">
          {onClose && (
            <button className="btn-close-deck" onClick={onClose} title="Close Deck">✕</button>
          )}
        </div>
      </header>

      {/* Global Alerts */}
      {msg.text && (
        <div className={`lanzar-alert ${msg.type}`}>
          <span>{msg.text}</span>
        </div>
      )}

      {/* Navigation Sub-Deck Tabs */}
      <nav className="my-lanzar-tabs">
        <button className={`tab-btn ${activeTab === 'overview' ? 'active' : ''}`} onClick={() => setActiveTab('overview')}>
          🛰 Overview
        </button>
        <button className={`tab-btn ${activeTab === 'profile' ? 'active' : ''}`} onClick={() => setActiveTab('profile')}>
          👤 Profile
        </button>
        <button className={`tab-btn ${activeTab === 'security' ? 'active' : ''}`} onClick={() => setActiveTab('security')}>
          🛡 Security &amp; MFA
        </button>
        <button className={`tab-btn ${activeTab === 'apps' ? 'active' : ''}`} onClick={() => setActiveTab('apps')}>
          📦 Applications
        </button>
        <button className={`tab-btn ${activeTab === 'founders' ? 'active' : ''}`} onClick={() => setActiveTab('founders')}>
          🎖 Founders
        </button>
        <button className={`tab-btn ${activeTab === 'privacy' ? 'active' : ''}`} onClick={() => setActiveTab('privacy')}>
          📜 Privacy
        </button>
      </nav>

      {/* Main Content Viewport */}
      <div className="my-lanzar-body">
        {/* =========================================
            TAB 1: OVERVIEW
           ========================================= */}
        {activeTab === 'overview' && (
          <div className="deck-panel">
            <div className="user-hero-card">
              <div className="hero-avatar-wrap">
                {profile?.avatarUrl ? (
                  <img src={profile.avatarUrl} alt={profile.displayName} className="hero-avatar" />
                ) : (
                  <div className="hero-avatar-placeholder">{profile?.displayName?.charAt(0) || 'L'}</div>
                )}
                {profile?.emailVerified && <span className="verified-check" title="Email Verified">✓</span>}
              </div>
              <div className="hero-identity">
                <div className="hero-name-row">
                  <h3 className="hero-name">{profile?.displayName || 'LANZAR Cadet'}</h3>
                  <span className="role-pill">{profile?.role?.toUpperCase() || 'USER'}</span>
                </div>
                <p className="hero-email">{profile?.email}</p>
                <div className="hero-badges-row">
                  {badges.length > 0 ? (
                    badges.map(b => (
                      <span key={b} className="founder-badge-pill">
                        ⭐ {b.replace(/_/g, ' ').toUpperCase()}
                      </span>
                    ))
                  ) : (
                    <span className="badge-empty">Standard Ecosystem Identity</span>
                  )}
                </div>
              </div>
            </div>

            {/* Quick Status Cards */}
            <div className="status-grid">
              <div className="status-card">
                <span className="status-label">EMAIL VERIFICATION</span>
                <span className={`status-val ${profile?.emailVerified ? 'nominal' : 'warning'}`}>
                  {profile?.emailVerified ? '● VERIFIED' : '○ PENDING VERIFICATION'}
                </span>
                {!profile?.emailVerified && (
                  <button className="link-action" onClick={handleTriggerPasswordReset}>Resend Link</button>
                )}
              </div>
              <div className="status-card">
                <span className="status-label">MULTI-FACTOR AUTH</span>
                <span className={`status-val ${mfaStatus?.mfaEnrolled ? 'nominal' : 'idle'}`}>
                  {mfaStatus?.mfaEnrolled ? '● TOTP ENROLLED' : '○ NOT CONFIGURED'}
                </span>
                <button className="link-action" onClick={() => setActiveTab('security')}>Configure</button>
              </div>
              <div className="status-card">
                <span className="status-label">ACTIVE SESSIONS</span>
                <span className="status-val nominal">● {sessions.length} DEVICES</span>
                <button className="link-action" onClick={() => setActiveTab('security')}>Inspect</button>
              </div>
              <div className="status-card">
                <span className="status-label">PHONE VERIFICATION</span>
                <span className={`status-val ${profile?.phoneVerified ? 'nominal' : 'idle'}`}>
                  {profile?.phoneVerified ? '● ' + profile.phoneNumber : '○ UNVERIFIED'}
                </span>
                <button className="link-action" onClick={() => setActiveTab('security')}>Manage</button>
              </div>
            </div>

            {/* Connected Apps Launchpad */}
            <h4 className="section-title">ECOSYSTEM LAUNCHPAD</h4>
            <div className="apps-grid">
              <a href="https://portal.lanzar.me" className="app-launch-card">
                <div className="app-icon">🏢</div>
                <div>
                  <div className="app-title">Client Portal</div>
                  <div className="app-desc">Invoices, projects &amp; tickets</div>
                </div>
              </a>
              <a href="https://pythos.lanzar.me" className="app-launch-card">
                <div className="app-icon">📐</div>
                <div>
                  <div className="app-title">Pythos AI</div>
                  <div className="app-desc">Autonomous Math &amp; Physics Tutor</div>
                </div>
              </a>
              <a href="https://tickets.lanzar.me" className="app-launch-card">
                <div className="app-icon">🎫</div>
                <div>
                  <div className="app-title">Support Queue</div>
                  <div className="app-desc">Live help desk &amp; triage</div>
                </div>
              </a>
              <a href="https://threadline.lanzar.me" className="app-launch-card">
                <div className="app-icon">🧵</div>
                <div>
                  <div className="app-title">Threadline</div>
                  <div className="app-desc">Enterprise software &amp; evidence</div>
                </div>
              </a>
            </div>
          </div>
        )}

        {/* =========================================
            TAB 2: PROFILE
           ========================================= */}
        {activeTab === 'profile' && (
          <div className="deck-panel">
            <h4 className="section-title">PERSONAL IDENTITY</h4>
            <form onSubmit={handleSaveProfile} className="deck-form">
              <div className="form-group">
                <label className="form-label">Display Name</label>
                <input 
                  type="text" 
                  className="form-input" 
                  value={displayName} 
                  onChange={e => setDisplayName(e.target.value)} 
                  required 
                  placeholder="Your full name or callsign"
                />
              </div>

              <div className="form-group">
                <label className="form-label">Email Address (Immutable UID)</label>
                <input 
                  type="email" 
                  className="form-input disabled" 
                  value={profile?.email || ''} 
                  disabled 
                  title="Contact operations to change primary email address"
                />
                <span className="field-hint">Primary email bound to cryptographic UID.</span>
              </div>

              <div className="form-group">
                <label className="form-label">Avatar Image URL (HTTPS)</label>
                <input 
                  type="url" 
                  className="form-input" 
                  value={avatarUrl} 
                  onChange={e => setAvatarUrl(e.target.value)} 
                  placeholder="https://storage.googleapis.com/.../avatar.webp"
                />
              </div>

              <div className="form-group">
                <label className="form-label">Short Bio</label>
                <textarea 
                  className="form-textarea" 
                  value={bio} 
                  onChange={e => setBio(e.target.value)} 
                  placeholder="Tell the LANZAR ecosystem about your background..."
                  rows="3"
                />
              </div>

              <button type="submit" className="btn-primary-deck" disabled={savingProfile}>
                {savingProfile ? 'SAVING...' : 'SAVE CHANGES'}
              </button>
            </form>
          </div>
        )}

        {/* =========================================
            TAB 3: SECURITY & MFA
           ========================================= */}
        {activeTab === 'security' && (
          <div className="deck-panel">
            <h4 className="section-title">CREDENTIAL &amp; MULTI-FACTOR DEFENSES</h4>

            {/* Password Management */}
            <div className="security-subpanel">
              <div>
                <h5 className="subpanel-title">Password Security</h5>
                <p className="subpanel-desc">Reset your password or dispatch a time-limited recovery link.</p>
              </div>
              <button className="btn-secondary-deck" onClick={handleTriggerPasswordReset}>
                SEND PASSWORD RESET EMAIL
              </button>
            </div>

            {/* Universal TOTP Authenticator (Google / Microsoft Authenticator) */}
            <div className="security-subpanel">
              <div>
                <h5 className="subpanel-title">Universal TOTP Authenticator (RFC 6238)</h5>
                <p className="subpanel-desc">
                  Compatible with <strong>Microsoft Authenticator</strong>, <strong>Google Authenticator</strong>, <strong>1Password</strong>, and <strong>Bitwarden</strong>.
                </p>
                {mfaStatus?.mfaEnrolled && (
                  <span className="nominal-tag">✓ ACTIVE AND ENROLLED</span>
                )}
              </div>
              {!mfaStatus?.mfaEnrolled && !totpSetup && (
                <button className="btn-secondary-deck" onClick={handleStartTotp} disabled={totpLoading}>
                  {totpLoading ? 'INITIALIZING...' : 'ENABLE AUTHENTICATOR'}
                </button>
              )}
            </div>

            {/* TOTP Setup Ceremony */}
            {totpSetup && (
              <div className="totp-setup-box">
                <h5 className="totp-setup-heading">Scan QR Code in Authenticator</h5>
                <p className="totp-instructions">
                  Open <strong>Google Authenticator</strong> or <strong>Microsoft Authenticator</strong>, tap Add Account, and scan the QR code below.
                </p>
                <div className="qr-container">
                  {/* Standard QR rendering via Google Charts zero-dependency safe image API */}
                  <img 
                    src={`https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent(totpSetup.otpauthUrl)}`} 
                    alt="TOTP QR Code" 
                    className="qr-image"
                  />
                </div>
                <div className="manual-key-wrap">
                  <span className="manual-key-label">Manual Setup Key:</span>
                  <code className="manual-key-code">{totpSetup.secret}</code>
                </div>

                <form onSubmit={handleEnableTotp} className="totp-verify-form">
                  <input 
                    type="text" 
                    className="form-input otp-input" 
                    placeholder="000000" 
                    maxLength="6" 
                    value={totpCode} 
                    onChange={e => setTotpCode(e.target.value.replace(/\D/g, ''))} 
                    required 
                  />
                  <div className="totp-btn-row">
                    <button type="submit" className="btn-primary-deck" disabled={totpLoading}>
                      {totpLoading ? 'CONFIRMING...' : 'VERIFY &amp; ACTIVATE'}
                    </button>
                    <button type="button" className="btn-cancel-deck" onClick={() => setTotpSetup(null)}>
                      CANCEL
                    </button>
                  </div>
                </form>
              </div>
            )}

            {/* Single-Use Recovery Codes Display */}
            {recoveryCodes.length > 0 && (
              <div className="recovery-codes-box">
                <h5 className="recovery-heading">⚠️ SAVE YOUR RECOVERY CODES</h5>
                <p className="recovery-desc">
                  Store these 8 single-use codes safely. If you lose access to your authenticator, each code can be used once to access your account.
                </p>
                <div className="recovery-grid">
                  {recoveryCodes.map(code => (
                    <code key={code} className="recovery-code-pill">{code}</code>
                  ))}
                </div>
                <button className="btn-secondary-deck" onClick={() => setRecoveryCodes([])}>
                  I HAVE SAVED THESE CODES
                </button>
              </div>
            )}

            {/* Phone Verification */}
            <div className="security-subpanel">
              <div>
                <h5 className="subpanel-title">Phone Number (E.164)</h5>
                <p className="subpanel-desc">Optional verified phone attribute for support lookup and security.</p>
                {profile?.phoneVerified && (
                  <span className="nominal-tag">✓ VERIFIED: {profile.phoneNumber}</span>
                )}
              </div>
              {!profile?.phoneVerified && !otpSent && (
                <form onSubmit={handleSendPhoneOtp} className="phone-mini-form">
                  <input 
                    type="tel" 
                    className="form-input phone-input" 
                    placeholder="+1 508 555 1234" 
                    value={phoneNumber} 
                    onChange={e => setPhoneNumber(e.target.value)} 
                    required 
                  />
                  <button type="submit" className="btn-secondary-deck" disabled={phoneLoading}>
                    {phoneLoading ? 'SENDING...' : 'SEND OTP'}
                  </button>
                </form>
              )}
            </div>

            {otpSent && !profile?.phoneVerified && (
              <form onSubmit={handleVerifyPhoneOtp} className="phone-verify-box">
                <span className="otp-prompt">Enter 6-digit code sent to {phoneNumber}:</span>
                <input 
                  type="text" 
                  className="form-input otp-input" 
                  maxLength="6" 
                  placeholder="000000" 
                  value={phoneCode} 
                  onChange={e => setPhoneCode(e.target.value.replace(/\D/g, ''))} 
                  required 
                />
                <button type="submit" className="btn-primary-deck" disabled={phoneLoading}>VERIFY PHONE</button>
                <button type="button" className="btn-cancel-deck" onClick={() => setOtpSent(false)}>CANCEL</button>
              </form>
            )}

            {/* Active Sessions Deck */}
            <div className="sessions-header-row">
              <h5 className="subpanel-title">Active Device Sessions</h5>
              <button className="btn-kill-all" onClick={handleRevokeAllSessions}>
                SIGN OUT EVERYWHERE
              </button>
            </div>
            <div className="sessions-list">
              {sessions.map(s => (
                <div key={s.sessionId} className={`session-card ${s.revoked ? 'revoked' : ''}`}>
                  <div className="session-icon">💻</div>
                  <div className="session-info">
                    <div className="session-name">
                      {s.deviceName} ({s.clientId})
                      {s.revoked && <span className="revoked-tag">REVOKED</span>}
                    </div>
                    <div className="session-meta">
                      IP: {s.ipAddress} • Last Seen: {new Date(s.lastSeenAt || s.createdAt).toLocaleString()}
                    </div>
                  </div>
                  {!s.revoked && (
                    <button className="btn-revoke-device" onClick={() => handleRevokeSession(s.sessionId)}>
                      REVOKE
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* =========================================
            TAB 4: APPLICATIONS
           ========================================= */}
        {activeTab === 'apps' && (
          <div className="deck-panel">
            <h4 className="section-title">AUTHORIZED ECOSYSTEM APPLICATIONS</h4>
            <div className="apps-detailed-list">
              <div className="app-detail-card">
                <div className="app-icon-wrap">🏢</div>
                <div className="app-detail-info">
                  <h5 className="app-card-title">LANZAR Client Portal</h5>
                  <p className="app-card-desc">Authoritative client dashboard for project invoices, support tickets, and service management.</p>
                  <span className="app-scope-tag">Scopes: profile, email, billing:read</span>
                </div>
                <a href="https://portal.lanzar.me" target="_blank" rel="noreferrer" className="btn-launch-app">OPEN ↗</a>
              </div>

              <div className="app-detail-card">
                <div className="app-icon-wrap">📐</div>
                <div className="app-detail-info">
                  <h5 className="app-card-title">Pythos AI Autonomous Tutor</h5>
                  <p className="app-card-desc">Socratic math &amp; physics tutoring with deterministic verification engine.</p>
                  <span className="app-scope-tag">Scopes: profile, learning_history, memory</span>
                </div>
                <a href="https://pythos.lanzar.me" target="_blank" rel="noreferrer" className="btn-launch-app">OPEN ↗</a>
              </div>

              <div className="app-detail-card">
                <div className="app-icon-wrap">🎫</div>
                <div className="app-detail-info">
                  <h5 className="app-card-title">LANZAR Support Desk (Tickets)</h5>
                  <p className="app-card-desc">Real-time technician queue and triage system.</p>
                  <span className="app-scope-tag">Scopes: profile, tickets:submit</span>
                </div>
                <a href="https://tickets.lanzar.me" target="_blank" rel="noreferrer" className="btn-launch-app">OPEN ↗</a>
              </div>

              <div className="app-detail-card">
                <div className="app-icon-wrap">🧵</div>
                <div className="app-detail-info">
                  <h5 className="app-card-title">Threadline Software</h5>
                  <p className="app-card-desc">Evidence and case analysis intelligence suite.</p>
                  <span className="app-scope-tag">Scopes: profile, cases:read</span>
                </div>
                <a href="https://threadline.lanzar.me" target="_blank" rel="noreferrer" className="btn-launch-app">OPEN ↗</a>
              </div>
            </div>
          </div>
        )}

        {/* =========================================
            TAB 5: FOUNDERS
           ========================================= */}
        {activeTab === 'founders' && (
          <div className="deck-panel">
            <h4 className="section-title">PRODUCT-SPECIFIC FOUNDER PROGRAMS</h4>
            <p className="deck-intro">
              Founder designations honor pioneer participants across individual LANZAR products. Each designation carries independent product-scoped privileges.
            </p>
            <div className="founders-grid">
              <div className={`founder-card ${badges.includes('lanzar_id_founder') ? 'earned' : 'locked'}`}>
                <div className="founder-icon">🚀</div>
                <h5 className="founder-title">LANZAR ID Pioneer</h5>
                <p className="founder-desc">Ecosystem-wide founding identity participant.</p>
                <span className="founder-status-tag">
                  {badges.includes('lanzar_id_founder') ? '★ EARNED &amp; ACTIVE' : 'LOCKED'}
                </span>
              </div>

              <div className={`founder-card ${badges.includes('pythos_founder') ? 'earned' : 'locked'}`}>
                <div className="founder-icon">📐</div>
                <h5 className="founder-title">Pythos Founding Scholar</h5>
                <p className="founder-desc">Pioneer cohort tutor testing &amp; curriculum contribution.</p>
                <span className="founder-status-tag">
                  {badges.includes('pythos_founder') ? '★ EARNED &amp; ACTIVE' : 'LOCKED'}
                </span>
              </div>

              <div className={`founder-card ${badges.includes('portal_founder') ? 'earned' : 'locked'}`}>
                <div className="founder-icon">🏢</div>
                <h5 className="founder-title">Portal Operations Founder</h5>
                <p className="founder-desc">Charter client organization on LANZAR Operations Deck.</p>
                <span className="founder-status-tag">
                  {badges.includes('portal_founder') ? '★ EARNED &amp; ACTIVE' : 'LOCKED'}
                </span>
              </div>

              <div className={`founder-card ${badges.includes('traveling_founder') ? 'earned' : 'locked'}`}>
                <div className="founder-icon">🌐</div>
                <h5 className="founder-title">Traveling Systems Founder</h5>
                <p className="founder-desc">Global mobile infrastructure &amp; field testing cohort.</p>
                <span className="founder-status-tag">
                  {badges.includes('traveling_founder') ? '★ EARNED &amp; ACTIVE' : 'LOCKED'}
                </span>
              </div>

              <div className={`founder-card ${badges.includes('threadline_founder') ? 'earned' : 'locked'}`}>
                <div className="founder-icon">🧵</div>
                <h5 className="founder-title">Threadline Intelligence Founder</h5>
                <p className="founder-desc">Charter intelligence &amp; evidence platform licensee.</p>
                <span className="founder-status-tag">
                  {badges.includes('threadline_founder') ? '★ EARNED &amp; ACTIVE' : 'LOCKED'}
                </span>
              </div>
            </div>
          </div>
        )}

        {/* =========================================
            TAB 6: PRIVACY & DATA ERASURE
           ========================================= */}
        {activeTab === 'privacy' && (
          <div className="deck-panel">
            <h4 className="section-title">COMMUNICATIONS &amp; PRIVACY</h4>

            {/* The Dispatch Newsletter Preferences (Amendment #003) */}
            <div className="security-subpanel">
              <div>
                <div className="dispatch-badge">THE DISPATCH</div>
                <h5 className="subpanel-title">The LANZAR Dispatch Newsletter</h5>
                <p className="subpanel-desc">
                  Direct news from the LANZAR universe. New products, development logs, and special announcements.
                </p>
                {dispatchSubscribed ? (
                  <span className="nominal-tag">✓ ACTIVE SUBSCRIBER</span>
                ) : (
                  <span className="idle-tag" style={{ color: '#94a3b8', fontSize: '0.72rem', display: 'inline-block', marginTop: '0.4rem' }}>
                    ○ NOT CURRENTLY SUBSCRIBED
                  </span>
                )}
              </div>
              {dispatchSubscribed ? (
                <button className="btn-secondary-deck" onClick={handleUnsubscribeDispatch}>
                  UNSUBSCRIBE
                </button>
              ) : (
                <button className="btn-primary-deck" onClick={handleSubscribeDispatch}>
                  SUBSCRIBE TO THE DISPATCH
                </button>
              )}
            </div>

            <div className="privacy-card">
              <div>
                <h5 className="subpanel-title">Export Personal Data (GDPR / CCPA)</h5>
                <p className="subpanel-desc">Download a complete JSON export of your personal profile, verified attributes, and metadata.</p>
              </div>
              <button className="btn-secondary-deck" onClick={handleExportData}>DOWNLOAD JSON EXPORT</button>
            </div>

            <div className="danger-zone">
              <h5 className="danger-title">PERMANENT ACCOUNT ERASURE</h5>
              <p className="danger-desc">
                Permanently deletes your LANZAR ID, active sessions, MFA authenticators, and all associated ecosystem records. This action is irreversible.
              </p>
              <button className="btn-danger-deck" onClick={() => setShowDeleteModal(true)}>
                DELETE MY ACCOUNT
              </button>
            </div>

            {/* Erasure Confirmation Modal */}
            {showDeleteModal && (
              <div className="modal-backdrop">
                <div className="modal-content-deck">
                  <h4 className="modal-title">CONFIRM ACCOUNT ERASURE</h4>
                  <p className="modal-warning">
                    This will permanently delete your identity across Pythos, Portal, Tickets, and all LANZAR products. Type <strong>DELETE</strong> below to confirm.
                  </p>
                  <input 
                    type="text" 
                    className="form-input modal-input" 
                    value={deleteConfirmationInput} 
                    onChange={e => setDeleteConfirmationInput(e.target.value)} 
                    placeholder="Type DELETE" 
                  />
                  <div className="modal-actions">
                    <button 
                      className="btn-danger-deck" 
                      disabled={deleteConfirmationInput !== 'DELETE' || deletingAccount} 
                      onClick={handleExecuteAccountErasure}
                    >
                      {deletingAccount ? 'ERASING...' : 'CONFIRM PERMANENT ERASURE'}
                    </button>
                    <button className="btn-cancel-deck" onClick={() => setShowDeleteModal(false)}>
                      CANCEL
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Footer Navigation Bar */}
      <footer className="my-lanzar-footer">
        <span className="footer-token-ver">Session Security: tokenVersion {profile?.tokenVersion || 1}</span>
        <button className="btn-sign-out" onClick={() => signOutUser()}>SIGN OUT OF LANZAR</button>
      </footer>
    </div>
  )
}
