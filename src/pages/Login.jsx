import { useState } from 'react'
import { 
  signInWithEmail, 
  sendPasswordReset, 
  signInWithGoogle, 
  registerWithEmail 
} from '../firebase/auth.js'
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
  const [recoveryCodes, setRecoveryCodes] = useState([])
  
  const [loading, setLoading] = useState(false)
  const [localError, setLocalError] = useState(null)
  const [successMsg, setSuccessMsg] = useState(null)

  const error = localError || globalAuthError

  const authBackendUrl = window.location.hostname === 'localhost' ? 'http://localhost:4001' : 'https://auth-api.lanzar.me'

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
  // MFA: Start Enrollment (Fetch Secret)
  // ==========================================
  const handleStartMfaEnrollment = async (user) => {
    setLoading(true)
    setLocalError(null)
    try {
      const idToken = await user.getIdToken()
      const res = await fetch(`${authBackendUrl}/mfa/totp/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken })
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error_description || 'Failed to start MFA setup.')
      setMfaEnrollSecret(data.secret)
      setMfaOtpauthUrl(data.otpauthUrl)
    } catch (err) {
      setLocalError(err.message)
    } finally {
      setLoading(false)
    }
  }

  // ==========================================
  // MFA: Verify Enrollment Code
  // ==========================================
  const handleCompleteMfaEnrollment = async (e, user) => {
    e.preventDefault()
    setLoading(true)
    setLocalError(null)
    try {
      const idToken = await user.getIdToken()
      const res = await fetch(`${authBackendUrl}/mfa/totp/enable`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          idToken,
          secret: mfaEnrollSecret,
          code: mfaCode.trim()
        })
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error_description || 'MFA code verification failed.')
      setRecoveryCodes(data.recoveryCodes || [])
      setSuccessMsg('MFA successfully enabled! Please copy and securely store your recovery codes.')
    } catch (err) {
      setLocalError(err.message)
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
    try {
      const res = await fetch(`${authBackendUrl}/mfa/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mfaSession: mfaChallenge.mfaSession,
          code: mfaCode.trim(),
          method: mfaMethod
        })
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error_description || 'MFA verification failed.')
      if (onMfaVerified) {
        onMfaVerified(data.mfaProof)
      }
    } catch (err) {
      setLocalError(err.message)
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
      return (
        <div className="login-panel mfa-panel">
          <h2 className="login-title">SECURITY SETUP: MFA</h2>
          <p className="login-desc">
            Administrator accounts require Multi-Factor Authentication. Please pair your authenticator app (Google Authenticator, Authy, or 1Password).
          </p>

          {!mfaEnrollSecret ? (
            <div>
              {error && <p className="error-msg">{error}</p>}
              <button 
                type="button" 
                className="primary-btn" 
                onClick={() => handleStartMfaEnrollment(mfaChallenge.user)}
                disabled={loading}
              >
                {loading ? 'INITIALIZING...' : 'GENERATE AUTHENTICATOR KEY'}
              </button>
            </div>
          ) : recoveryCodes.length === 0 ? (
            <form onSubmit={(e) => handleCompleteMfaEnrollment(e, mfaChallenge.user)} className="login-form">
              <div className="secret-display-box">
                <span className="secret-label">AUTHENTICATOR SECRET KEY:</span>
                <code className="secret-code">{mfaEnrollSecret}</code>
                <p className="secret-hint">Add this key to your authenticator app.</p>
              </div>

              <div className="form-group">
                <label htmlFor="mfa-verify-code">6-DIGIT VERIFICATION CODE</label>
                <input 
                  id="mfa-verify-code"
                  type="text" 
                  maxLength={6}
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value)}
                  placeholder="e.g. 123456"
                  required
                  disabled={loading}
                  autoFocus
                />
              </div>

              {error && <p className="error-msg">{error}</p>}

              <button type="submit" className="primary-btn" disabled={loading}>
                {loading ? 'VERIFYING...' : 'CONFIRM & ACTIVATE MFA'}
              </button>
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

        {/* Newsletter Opt-In Checkbox (Phase 1 Requirement) */}
        {mode === 'register' && (
          <div className="checkbox-container">
            <input 
              type="checkbox" 
              id="dispatch-optin"
              checked={dispatchOptIn}
              onChange={(e) => setDispatchOptIn(e.target.checked)}
              disabled={loading}
            />
            <label htmlFor="dispatch-optin" className="checkbox-label">
              Send me <strong>The LANZAR Dispatch</strong> — news, project updates, new services, and occasional offers.
            </label>
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
    </div>
  )
}
