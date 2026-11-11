import { useState, useEffect, useCallback } from 'react'
import { 
  signInWithEmail, 
  sendPasswordReset, 
  signInWithGoogle, 
  registerWithEmail 
} from '../firebase/auth.js'
import { getAuthApiUrl } from '../config/env.js'
import TotpQrCode from '../components/TotpQrCode.jsx'
import './Login.css'

export default function Login({ 
  authError: globalAuthError, 
  unauthorized, 
  handleSignOut,
  mfaChallenge,
  onMfaVerified
}) {
  // Mode: 'signin' | 'register' | 'reset'
  const [mode, setMode] = useState('signin')
  
  // Sign In & Registration form state
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [fullName, setFullName] = useState('')
  const [businessName, setBusinessName] = useState('')
  const [dispatchOptIn, setDispatchOptIn] = useState(false) // MANDATORY: Unchecked by default
  
  // MFA Form State
  const [mfaCode, setMfaCode] = useState('')
  const [mfaMethod, setMfaMethod] = useState('totp') // 'totp' | 'recovery'
  const [mfaEnrollSecret, setMfaEnrollSecret] = useState(null)
  const [mfaOtpauthUrl, setMfaOtpauthUrl] = useState(null)
  const [mfaInitLoading, setMfaInitLoading] = useState(false)
  const [mfaInitError, setMfaInitError] = useState(null)
  const [showManualKey, setShowManualKey] = useState(false)
  const [copiedKey, setCopiedKey] = useState(false)
  const [recoveryCodes, setRecoveryCodes] = useState([])
  
  const [loading, setLoading] = useState(false)
  const [localError, setLocalError] = useState(null)
  const [successMsg, setSuccessMsg] = useState(null)

  const error = localError || globalAuthError

  const authBackendUrl = getAuthApiUrl()

  // ==========================================
  // MFA: Start Enrollment (Fetch Secret & URI)
  // ==========================================
  const handleStartMfaEnrollment = useCallback(async (user) => {
    if (!user) return
    setMfaInitLoading(true)
    setMfaInitError(null)
    setLocalError(null)
    setMfaCode('')
    setShowManualKey(false)
    setCopiedKey(false)
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 15000)
    try {
      const idToken = await user.getIdToken()
      const res = await fetch(`${authBackendUrl}/mfa/totp/setup`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${idToken}`
        },
        body: JSON.stringify({ idToken }),
        signal: controller.signal
      })
      clearTimeout(timer)
      const data = await res.json()
      if (!res.ok) throw new Error(data.error_description || 'Failed to start MFA setup.')
      if (!data.secret || !data.otpauthUrl || !data.otpauthUrl.startsWith('otpauth://totp/')) {
        throw new Error('Server returned an incomplete MFA provisioning payload. Please retry.')
      }
      setMfaEnrollSecret(data.secret)
      setMfaOtpauthUrl(data.otpauthUrl)
    } catch (err) {
      clearTimeout(timer)
      const isTimeout = err.name === 'AbortError'
      setMfaInitError(isTimeout ? 'MFA setup request timed out. Please check your connection and retry.' : err.message)
    } finally {
      setMfaInitLoading(false)
    }
  }, [authBackendUrl])

  // Auto-start MFA enrollment when an admin lands on enrollment screen
  useEffect(() => {
    if (
      mfaChallenge?.required &&
      mfaChallenge?.enrollmentRequired &&
      mfaChallenge?.user &&
      !mfaEnrollSecret &&
      !mfaInitLoading &&
      !mfaInitError &&
      recoveryCodes.length === 0
    ) {
      handleStartMfaEnrollment(mfaChallenge.user)
    }
  }, [mfaChallenge, mfaEnrollSecret, mfaInitLoading, mfaInitError, recoveryCodes.length, handleStartMfaEnrollment])

  // ==========================================
  // Sign In Handler
  // ==========================================
  const handleLogin = async (e) => {
    e.preventDefault()
    setLoading(true)
    setLocalError(null)
    setSuccessMsg(null)
    try {
      await signInWithEmail(email, password)
    } catch (err) {
      let message = 'Incorrect email or password.'
      if (err.code === 'auth/invalid-email') message = 'Please enter a valid email address.'
      if (err.code === 'auth/user-not-found' || err.code === 'auth/wrong-password') message = 'Invalid email or password.'
      if (err.code === 'auth/too-many-requests') message = 'Account temporarily disabled due to too many failed attempts.'
      setLocalError(message)
    } finally {
      setLoading(false)
    }
  }

  // ==========================================
  // Self-Service Registration Handler
  // ==========================================
  const handleRegister = async (e) => {
    e.preventDefault()
    setLoading(true)
    setLocalError(null)
    setSuccessMsg(null)

    // Validation
    if (!fullName.trim()) {
      setLocalError('Please enter your full name.')
      setLoading(false)
      return
    }

    if (password.length < 8) {
      setLocalError('Password must be at least 8 characters long.')
      setLoading(false)
      return
    }

    if (!/\d/.test(password)) {
      setLocalError('Password must contain at least one numeric digit.')
      setLoading(false)
      return
    }

    if (password !== confirmPassword) {
      setLocalError('Passwords do not match.')
      setLoading(false)
      return
    }

    try {
      // 1. Create user in Firebase Auth
      const newUser = await registerWithEmail(email, password, fullName.trim())
      const idToken = await newUser.getIdToken()

      // 2. Call server-controlled provisioning endpoint
      const provRes = await fetch(`${authBackendUrl}/provision`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          idToken,
          fullName: fullName.trim(),
          businessName: businessName.trim(),
          dispatchOptIn
        })
      })

      if (!provRes.ok) {
        console.warn('[AUTH] Server provisioning warning, proceeding with session')
      }

      setSuccessMsg('Account created successfully! Connecting to LANZAR...')
    } catch (err) {
      let message = 'Registration failed. Please check your information.'
      if (err.code === 'auth/email-already-in-use') {
        message = 'An account with this email address already exists. Please sign in.'
      } else if (err.code === 'auth/invalid-email') {
        message = 'Please enter a valid email address.'
      } else if (err.code === 'auth/weak-password') {
        message = 'Password is too weak. Please use at least 8 characters with numbers.'
      }
      setLocalError(message)
    } finally {
      setLoading(false)
    }
  }

  // ==========================================
  // Google Sign In Handler
  // ==========================================
  const handleGoogleSignIn = async () => {
    setLoading(true)
    setLocalError(null)
    setSuccessMsg(null)

    try {
      const user = await signInWithGoogle()
      const idToken = await user.getIdToken()
      // Auto-provision on Google sign-in
      await fetch(`${authBackendUrl}/provision`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          idToken,
          fullName: user.displayName,
          businessName: '',
          dispatchOptIn: false
        })
      }).catch(err => console.warn('Google auto-provision error:', err.message))
    } catch (err) {
      let message = 'Something went wrong while signing you in with Google. Please try again.'
      if (err.code === 'auth/unauthorized-domain') {
        message = 'This domain is not authorized for Google Sign-In.'
      } else if (err.code === 'auth/popup-closed-by-user') {
        message = 'The sign-in popup was closed before completing authentication.'
      }
      setLocalError(message)
    } finally {
      setLoading(false)
    }
  }

  // ==========================================
  // Password Reset Handler
  // ==========================================
  const handleReset = async (e) => {
    e.preventDefault()
    setLoading(true)
    setLocalError(null)
    try {
      await sendPasswordReset(email)
      setSuccessMsg('A password reset link has been sent to your email.')
      setEmail('')
    } catch (err) {
      setLocalError('Failed to send reset email. Please verify your email address.')
    } finally {
      setLoading(false)
    }
  }

  // ==========================================
  // MFA: Copy Setup Key Helper
  // ==========================================
  const handleCopyManualKey = async () => {
    if (!mfaEnrollSecret || !navigator?.clipboard?.writeText) return
    try {
      await navigator.clipboard.writeText(mfaEnrollSecret)
      setCopiedKey(true)
      setTimeout(() => setCopiedKey(false), 2000)
    } catch {
      setCopiedKey(false)
    }
  }

  // ==========================================
  // MFA: Verify Enrollment Code
  // ==========================================
  const handleCompleteMfaEnrollment = async (e, user) => {
    e.preventDefault()
    if (!user) return
    const sanitizedCode = mfaCode.trim()
    if (!/^\d{6}$/.test(sanitizedCode)) {
      setLocalError('Please enter a valid 6-digit verification code.')
      return
    }
    setLoading(true)
    setLocalError(null)
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 15000)
    try {
      const idToken = await user.getIdToken()
      const res = await fetch(`${authBackendUrl}/mfa/totp/enable`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${idToken}`
        },
        body: JSON.stringify({
          idToken,
          code: sanitizedCode
        }),
        signal: controller.signal
      })
      clearTimeout(timer)
      const data = await res.json()
      if (!res.ok) throw new Error(data.error_description || 'MFA code verification failed.')
      setRecoveryCodes(data.recoveryCodes || [])
      setSuccessMsg('MFA successfully enabled! Please copy and securely store your recovery codes.')
    } catch (err) {
      clearTimeout(timer)
      const isTimeout = err.name === 'AbortError'
      setLocalError(isTimeout ? 'MFA confirmation request timed out. Please try again.' : err.message)
    } finally {
      setLoading(false)
    }
  }

  // ==========================================
  // MFA: Submit Verification Challenge
  // ==========================================
  const handleSubmitMfaChallenge = async (e) => {
    e.preventDefault()
    setLoading(true)
    setLocalError(null)
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 15000)
    try {
      const res = await fetch(`${authBackendUrl}/mfa/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mfaSession: mfaChallenge.mfaSession,
          code: mfaCode.trim(),
          method: mfaMethod
        }),
        signal: controller.signal
      })
      clearTimeout(timer)
      const data = await res.json()
      if (!res.ok) throw new Error(data.error_description || 'MFA verification failed.')
      if (onMfaVerified) {
        onMfaVerified(data.mfaProof)
      }
    } catch (err) {
      clearTimeout(timer)
      const isTimeout = err.name === 'AbortError'
      setLocalError(isTimeout ? 'Verification timed out. Please try again.' : err.message)
    } finally {
      setLoading(false)
    }
  }

  // ==========================================
  // RENDER: Access Denied Screen
  // ==========================================
  if (unauthorized) {
    return (
      <div className="login-panel">
        <h2 className="login-title">ACCESS DENIED</h2>
        <p className="login-desc">You do not have customer access to this portal.</p>
        {error && <p className="error-msg">{error}</p>}
        <button className="primary-btn" onClick={handleSignOut}>SIGN OUT</button>
      </div>
    )
  }

  // ==========================================
  // RENDER: MFA Challenge & Enrollment Screen
  // ==========================================
  if (mfaChallenge && mfaChallenge.required) {
    if (mfaChallenge.enrollmentRequired) {
      const activeInitError = mfaInitError || (!mfaEnrollSecret && error)

      return (
        <div className="login-panel mfa-panel">
          <h2 className="login-title">SECURITY SETUP: MFA</h2>
          <p className="login-desc">
            Administrator accounts require Multi-Factor Authentication. Set up an authenticator app to secure your account.
          </p>

          {!mfaEnrollSecret || !mfaOtpauthUrl ? (
            <div style={{ textAlign: 'center', padding: '1rem 0' }}>
              {activeInitError && <p className="error-msg" style={{ marginBottom: '1rem' }}>{activeInitError}</p>}
              {mfaInitLoading ? (
                <div>
                  <div className="lanzar-spinner" style={{ width: 32, height: 32, margin: '0 auto 1rem auto' }}></div>
                  <p style={{ color: '#475569', fontSize: '0.85rem', letterSpacing: '0.05em', fontWeight: 700 }}>INITIALIZING AUTHENTICATOR KEY...</p>
                </div>
              ) : (
                <button 
                  type="button" 
                  className="primary-btn" 
                  onClick={() => handleStartMfaEnrollment(mfaChallenge.user)}
                >
                  {activeInitError ? 'RETRY SETUP' : 'GENERATE AUTHENTICATOR QR'}
                </button>
              )}
            </div>
          ) : recoveryCodes.length === 0 ? (
            <form onSubmit={(e) => handleCompleteMfaEnrollment(e, mfaChallenge.user)} className="login-form">
              <div className="qr-enrollment-box">
                <p className="qr-instruction">Scan this QR code with your authenticator app.</p>
                <p className="qr-supported-apps">
                  Compatible with Microsoft Authenticator, Google Authenticator, Authy, 1Password, and other TOTP-compatible apps.
                </p>
                <TotpQrCode otpauthUrl={mfaOtpauthUrl} size={184} />
                <div className="manual-key-toggle-wrap">
                  <button
                    type="button"
                    className="text-link manual-key-toggle"
                    aria-expanded={showManualKey}
                    aria-controls="manual-setup-key-panel"
                    onClick={() => setShowManualKey((prev) => !prev)}
                  >
                    {showManualKey ? 'Hide manual setup key' : "Can't scan? Enter setup key manually"}
                  </button>
                </div>

                {showManualKey && (
                  <div id="manual-setup-key-panel" className="secret-display-box manual-fallback-box">
                    <div className="manual-key-header">
                      <span className="secret-label">MANUAL SETUP KEY</span>
                      <button
                        type="button"
                        className="copy-key-btn"
                        onClick={handleCopyManualKey}
                      >
                        {copiedKey ? 'COPIED' : 'COPY KEY'}
                      </button>
                    </div>
                    <code className="secret-code">{mfaEnrollSecret}</code>
                    <p className="secret-hint">Type: Time-based (TOTP) · Algorithm: SHA1 · Digits: 6 · Period: 30s</p>
                  </div>
                )}
              </div>

              <div className="form-group">
                <label htmlFor="mfa-verify-code">6-DIGIT VERIFICATION CODE</label>
                <input 
                  id="mfa-verify-code"
                  className="mfa-otp-input"
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  pattern="[0-9]{6}"
                  maxLength={6}
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  placeholder="123456"
                  required
                  disabled={loading || mfaInitLoading}
                  autoFocus
                />
              </div>

              {error && <p className="error-msg">{error}</p>}

              <button
                type="submit"
                className="primary-btn"
                disabled={loading || mfaInitLoading || mfaCode.trim().length !== 6}
              >
                {loading ? 'VERIFYING...' : 'CONFIRM & ACTIVATE MFA'}
              </button>

              <div className="mfa-secondary-actions">
                <button
                  type="button"
                  className="text-link"
                  disabled={loading || mfaInitLoading}
                  onClick={() => handleStartMfaEnrollment(mfaChallenge.user)}
                >
                  {mfaInitLoading ? 'Generating new QR code...' : 'Generate new QR code'}
                </button>
              </div>
            </form>
          ) : (
            <div className="recovery-codes-box">
              <p className="success-msg">{successMsg}</p>
              <h4 className="recovery-title">SINGLE-USE RECOVERY CODES</h4>
              <p className="recovery-desc">Store these codes in a safe place. If you lose your authenticator, each code can be used once to access your account.</p>
              <div className="recovery-code-grid">
                {recoveryCodes.map((code, idx) => (
                  <div key={idx} className="recovery-code-pill">{code}</div>
                ))}
              </div>
              <button 
                type="button" 
                className="primary-btn" 
                style={{ marginTop: '1rem' }}
                onClick={() => window.location.reload()}
              >
                CONTINUE TO PORTAL
              </button>
            </div>
          )}
        </div>
      )
    }

    // Existing MFA Challenge
    return (
      <div className="login-panel mfa-panel">
        <h2 className="login-title">TWO-FACTOR CHALLENGE</h2>
        <p className="login-desc">
          {mfaMethod === 'totp' 
            ? 'Enter the 6-digit verification code from your authenticator app.'
            : 'Enter one of your single-use recovery codes (format: XXXX-XXXX).'}
        </p>

        <form onSubmit={handleSubmitMfaChallenge} className="login-form">
          <div className="form-group">
            <label htmlFor="mfa-challenge-input">
              {mfaMethod === 'totp' ? 'VERIFICATION CODE' : 'RECOVERY CODE'}
            </label>
            <input 
              id="mfa-challenge-input"
              type="text"
              maxLength={mfaMethod === 'totp' ? 6 : 9}
              value={mfaCode}
              onChange={(e) => setMfaCode(e.target.value)}
              placeholder={mfaMethod === 'totp' ? '123456' : 'A1B2-C3D4'}
              required
              disabled={loading}
              autoFocus
            />
          </div>

          <div style={{ marginBottom: '1rem', textAlign: 'right' }}>
            <button 
              type="button" 
              className="text-link"
              onClick={() => {
                setMfaMethod(mfaMethod === 'totp' ? 'recovery' : 'totp')
                setMfaCode('')
              }}
            >
              {mfaMethod === 'totp' ? 'Use a recovery code' : 'Use authenticator app'}
            </button>
          </div>

          {error && <p className="error-msg">{error}</p>}

          <button type="submit" className="primary-btn" disabled={loading}>
            {loading ? 'VERIFYING...' : 'VERIFY & SIGN IN'}
          </button>
        </form>
      </div>
    )
  }

  // ==========================================
  // RENDER: Unified Sign In / Create Account
  // ==========================================
  return (
    <div className="login-panel">
      {/* Tab Navigation */}
      {mode !== 'reset' && (
        <div className="auth-tab-bar">
          <button 
            type="button" 
            className={`auth-tab-btn ${mode === 'signin' ? 'active' : ''}`}
            onClick={() => { setMode('signin'); setLocalError(null); setSuccessMsg(null); }}
          >
            SIGN IN
          </button>
          <button 
            type="button" 
            className={`auth-tab-btn ${mode === 'register' ? 'active' : ''}`}
            onClick={() => { setMode('register'); setLocalError(null); setSuccessMsg(null); }}
          >
            CREATE ACCOUNT
          </button>
        </div>
      )}

      <h2 className="login-title">
        {mode === 'reset' ? 'RESET PASSWORD' : (mode === 'register' ? 'LANZAR REGISTRATION' : 'LANZAR IDENTITY')}
      </h2>

      <p className="login-desc">
        {mode === 'reset' 
          ? 'Enter your email address to receive a password reset link.' 
          : (mode === 'register'
              ? 'Create your LANZAR ID for unified access to portal, support, and services.'
              : 'Authenticate once to securely access the entire LANZAR ecosystem.')}
      </p>

      <form onSubmit={mode === 'reset' ? handleReset : (mode === 'register' ? handleRegister : handleLogin)} className="login-form">
        
        {/* Registration Specific Fields */}
        {mode === 'register' && (
          <>
            <div className="form-group">
              <label htmlFor="reg-name">FULL NAME *</label>
              <input 
                id="reg-name"
                type="text" 
                value={fullName} 
                onChange={(e) => setFullName(e.target.value)} 
                placeholder="e.g. Alex Morgan"
                required 
                disabled={loading}
              />
            </div>

            <div className="form-group">
              <label htmlFor="reg-business">BUSINESS / ORGANIZATION (OPTIONAL)</label>
              <input 
                id="reg-business"
                type="text" 
                value={businessName} 
                onChange={(e) => setBusinessName(e.target.value)} 
                placeholder="e.g. Acme Corp"
                disabled={loading}
              />
            </div>
          </>
        )}

        <div className="form-group">
          <label htmlFor="login-email">EMAIL ADDRESS *</label>
          <input 
            id="login-email"
            type="email" 
            value={email} 
            onChange={(e) => setEmail(e.target.value)} 
            placeholder="e.g. customer@example.com"
            required 
            disabled={loading}
            aria-required="true"
          />
        </div>

        {mode !== 'reset' && (
          <div className="form-group">
            <div className="label-row">
              <label htmlFor="login-password">PASSWORD *</label>
              {mode === 'signin' && (
                <button type="button" className="text-link" onClick={() => setMode('reset')} aria-label="Forgot Password?">Forgot?</button>
              )}
            </div>
            <input 
              id="login-password"
              type="password" 
              value={password} 
              onChange={(e) => setPassword(e.target.value)} 
              placeholder="•••••••••"
              required 
              disabled={loading}
              aria-required="true"
            />
          </div>
        )}

        {mode === 'register' && (
          <div className="form-group">
            <label htmlFor="reg-confirm-password">CONFIRM PASSWORD *</label>
            <input 
              id="reg-confirm-password"
              type="password" 
              value={confirmPassword} 
              onChange={(e) => setConfirmPassword(e.target.value)} 
              placeholder="•••••••••"
              required 
              disabled={loading}
            />
          </div>
        )}

        {/* The Dispatch Newsletter Promotion (Amendment #003) */}
        {mode === 'register' && (
          <div className="dispatch-promo-box">
            <div className="dispatch-badge">COMMUNITY INTELLIGENCE</div>
            <h4 className="dispatch-heading">GET THE DISPATCH</h4>
            <p className="dispatch-tagline">
              News from the LANZAR universe. New products, launches, development updates, special announcements, and things we&apos;re building.
            </p>
            <div className="checkbox-container dispatch-checkbox-row">
              <input 
                type="checkbox" 
                id="dispatch-optin"
                checked={dispatchOptIn}
                onChange={(e) => setDispatchOptIn(e.target.checked)}
                disabled={loading}
              />
              <label htmlFor="dispatch-optin" className="checkbox-label">
                <strong>Subscribe to THE DISPATCH</strong> and stay connected.
              </label>
            </div>
          </div>
        )}

        {error && <p className="error-msg">{error}</p>}
        {successMsg && <p className="success-msg">{successMsg}</p>}

        <div className="form-actions">
          {mode === 'reset' && (
            <button type="button" className="text-link" onClick={() => setMode('signin')} disabled={loading}>
              &larr; Back to Sign In
            </button>
          )}
          <button type="submit" className="primary-btn" disabled={loading}>
            {loading 
              ? 'PROCESSING...' 
              : (mode === 'reset' ? 'SEND RESET LINK' : (mode === 'register' ? 'CREATE ACCOUNT' : 'SIGN IN'))}
          </button>
        </div>

        {mode === 'signin' && (
          <>
            <div className="signin-divider">
              <span className="signin-divider-line"></span>
              <span className="signin-divider-text">OR</span>
              <span className="signin-divider-line"></span>
            </div>

            <button
              className="google-signin-button"
              type="button"
              onClick={handleGoogleSignIn}
              disabled={loading}
            >
              <svg className="google-icon" viewBox="0 0 24 24" aria-hidden="true">
                <path fill="#4285F4" d="M21.35 12.27c0-.71-.06-1.4-.18-2.06H12v3.9h5.24a4.48 4.48 0 0 1-1.94 2.94v2.45h3.14c1.84-1.69 2.91-4.18 2.91-7.23Z" />
                <path fill="#34A853" d="M12 21.67c2.63 0 4.84-.87 6.45-2.36l-3.14-2.45c-.87.58-1.98.92-3.31.92-2.54 0-4.69-1.72-5.46-4.03H3.3A9.75 9.75 0 0 0 12 21.67Z" />
                <path fill="#FBBC05" d="M6.54 13.75A5.86 5.86 0 0 1 6.23 12c0-.61.11-1.2.31-1.75V7.72H3.3A9.75 9.75 0 0 0 2.25 12c0 1.57.38 3.06 1.05 4.28l3.24-2.53Z" />
                <path fill="#EA4335" d="M12 6.22c1.43 0 2.72.49 3.73 1.46l2.8-2.8C16.84 3.29 14.63 2.33 12 2.33a9.74 9.74 0 0 0-8.7 5.39l3.24 2.53C6.85 7.94 9 6.22 12 6.22Z" />
              </svg>
              SIGN IN WITH GOOGLE
            </button>
          </>
        )}
      </form>

      <div style={{ marginTop: '1.5rem', paddingTop: '1rem', borderTop: '1px solid rgba(255,255,255,0.1)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.8rem', flexWrap: 'wrap', gap: '0.5rem' }}>
        <a href="https://lanzar.me" style={{ color: '#94a3b8', textDecoration: 'none', fontWeight: 600 }}>&larr; Return to LANZAR.me</a>
        <a href="tel:+15085718819" style={{ color: '#f46b45', textDecoration: 'none', fontWeight: 700 }}>📞 Dispatch: (508) 571-8819</a>
      </div>
    </div>
  )
}
