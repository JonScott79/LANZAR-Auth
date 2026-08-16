import { useState } from 'react'
import { signInWithEmail, sendPasswordReset, signInWithGoogle } from '../firebase/auth.js'
import './Login.css'

export default function Login({ authError: globalAuthError, unauthorized, handleSignOut }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [localError, setLocalError] = useState(null)
  const [successMsg, setSuccessMsg] = useState(null)
  const [resetMode, setResetMode] = useState(false)

  const error = localError || globalAuthError

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
      if (err.code === 'auth/too-many-requests') message = 'Account temporarily disabled due to too many failed attempts.'
      setLocalError(message)
      setLoading(false)
    }
  }

  const handleGoogleSignIn = async () => {
    setLoading(true)
    setLocalError(null)
    setSuccessMsg(null)

    try {
      await signInWithGoogle()
      // App.jsx's onAuthStateChanged will handle the routing and authorization check
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

  return (
    <div className="login-panel">
      <h2 className="login-title">{resetMode ? 'RESET PASSWORD' : 'LANZAR IDENTITY'}</h2>
      <p className="login-desc">
        {resetMode 
          ? 'Enter your email address to receive a password reset link.' 
          : 'Authenticate once to securely access the entire LANZAR ecosystem.'}
      </p>

      <form onSubmit={resetMode ? handleReset : handleLogin} className="login-form">
        <div className="form-group">
          <label htmlFor="login-email">EMAIL ADDRESS</label>
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

        {!resetMode && (
          <div className="form-group">
            <div className="label-row">
              <label htmlFor="login-password">PASSWORD</label>
              <button type="button" className="text-link" onClick={() => setResetMode(true)} aria-label="Forgot Password?">Forgot?</button>
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

        {error && <p className="error-msg">{error}</p>}
        {successMsg && <p className="success-msg">{successMsg}</p>}

        <div className="form-actions">
          {resetMode && (
            <button type="button" className="text-link" onClick={() => setResetMode(false)} disabled={loading}>
              &larr; Back to Login
            </button>
          )}
          <button type="submit" className="primary-btn" disabled={loading}>
            {loading ? 'PROCESSING...' : (resetMode ? 'SEND LINK' : 'SIGN IN')}
          </button>
        </div>

        {!resetMode && (
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
              <svg
                className="google-icon"
                viewBox="0 0 24 24"
                aria-hidden="true"
              >
                <path
                  fill="#4285F4"
                  d="M21.35 12.27c0-.71-.06-1.4-.18-2.06H12v3.9h5.24a4.48 4.48 0 0 1-1.94 2.94v2.45h3.14c1.84-1.69 2.91-4.18 2.91-7.23Z"
                />
                <path
                  fill="#34A853"
                  d="M12 21.67c2.63 0 4.84-.87 6.45-2.36l-3.14-2.45c-.87.58-1.98.92-3.31.92-2.54 0-4.69-1.72-5.46-4.03H3.3A9.75 9.75 0 0 0 12 21.67Z"
                />
                <path
                  fill="#FBBC05"
                  d="M6.54 13.75A5.86 5.86 0 0 1 6.23 12c0-.61.11-1.2.31-1.75V7.72H3.3A9.75 9.75 0 0 0 2.25 12c0 1.57.38 3.06 1.05 4.28l3.24-2.53Z"
                />
                <path
                  fill="#EA4335"
                  d="M12 6.22c1.43 0 2.72.49 3.73 1.46l2.8-2.8C16.84 3.29 14.63 2.33 12 2.33a9.74 9.74 0 0 0-8.7 5.39l3.24 2.53C6.85 7.94 9 6.22 12 6.22Z"
                />
              </svg>
              SIGN IN WITH GOOGLE
            </button>
          </>
        )}
      </form>
    </div>
  )
}
