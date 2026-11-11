import { useState, useEffect, useRef } from 'react'
import { 
  LanzarAuth, 
  DEVELOPMENT_CONFIG, 
  PRODUCTION_CONFIG 
} from '../sdk/lanzar-auth-modal.js'
import { signInWithCustomToken } from '../firebase/auth.js'
import { withTimeout } from '../utils/asyncTimeout.js'
import './Login.css'

export default function Login({
  authError: globalAuthError,
  unauthorized,
  handleSignOut,
  onRetry,
  errorTitle,
  errorDescription,
  retryLabel = 'RETRY INITIALIZATION'
}) {
  const [loadingMsg, setLoadingMsg] = useState('')
  const [localError, setLocalError] = useState(null)
  const modalRef = useRef(null)
  const loadingMsgRef = useRef('')

  useEffect(() => {
    loadingMsgRef.current = loadingMsg
  }, [loadingMsg])

  const activeConfig = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? DEVELOPMENT_CONFIG
    : PRODUCTION_CONFIG

  // Manage <lanzar-auth-modal> lifecycle and event listeners cleanly
  useEffect(() => {
    const modal = modalRef.current
    if (!modal) return

    modal._config = activeConfig

    const handleAuthenticated = async (event) => {
      const detail = event.detail
      if (!detail || !detail.code || !detail.codeVerifier) {
        setLocalError('Authentication handshake failed: missing code or verifier.')
        setLoadingMsg('')
        return
      }

      setLoadingMsg('Completing secure login...')
      setLocalError(null)

      try {
        const session = await LanzarAuth.exchangeCodeForSession({
          code: detail.code,
          clientId: 'portal',
          redirectUri: window.location.origin,
          codeVerifier: detail.codeVerifier,
          timeoutMs: 15000
        }, activeConfig)

        if (session.session_id) {
          sessionStorage.setItem('lanzar_session_id', session.session_id)
        }

        await withTimeout(
          signInWithCustomToken(session.custom_token),
          15000,
          'Firebase authentication timed out. Please try again.',
          'firebase_signin'
        )
      } catch (err) {
        console.error('[AUTH MODAL ERROR]', err)
        setLocalError(err.message || 'Failed to exchange authorization code for session.')
        setLoadingMsg('')
      }
    }

    const handleClosed = () => {
      if (loadingMsgRef.current === 'Opening LANZAR ID...') {
        setLoadingMsg('')
      }
    }

    modal.addEventListener('lanzar:authenticated', handleAuthenticated)
    modal.addEventListener('lanzar:closed', handleClosed)

    return () => {
      modal.removeEventListener('lanzar:authenticated', handleAuthenticated)
      modal.removeEventListener('lanzar:closed', handleClosed)
    }
  }, [activeConfig])

  // Option 1: Embedded Modal flow (Default)
  const handleModalLogin = () => {
    setLocalError(null)
    setLoadingMsg('Opening LANZAR ID...')
    const modal = modalRef.current
    if (modal && typeof modal.openWithPkce === 'function') {
      modal.openWithPkce({
        clientId: 'portal',
        redirectUri: window.location.origin
      }).catch((err) => {
        setLocalError(err.message || 'Failed to open authentication modal.')
        setLoadingMsg('')
      })
    } else {
      setLocalError('Authentication modal component not initialized.')
      setLoadingMsg('')
    }
  }

  // Option 2: Popup Window flow (Fallback)
  const handlePopupLogin = async () => {
    setLocalError(null)
    setLoadingMsg('Opening authentication popup...')
    try {
      const result = await LanzarAuth.openPopup({
        clientId: 'portal',
        redirectUri: window.location.origin
      }, activeConfig)

      setLoadingMsg('Completing secure login...')
      const session = await LanzarAuth.exchangeCodeForSession({
        code: result.code,
        clientId: 'portal',
        redirectUri: window.location.origin,
        codeVerifier: result.codeVerifier,
        timeoutMs: 15000
      }, activeConfig)

      if (session.session_id) {
        sessionStorage.setItem('lanzar_session_id', session.session_id)
      }

      await withTimeout(
        signInWithCustomToken(session.custom_token),
        15000,
        'Firebase authentication timed out. Please try again.',
        'firebase_signin'
      )
    } catch (err) {
      console.error('[AUTH POPUP ERROR]', err)
      setLocalError(err.message || 'Popup authentication failed.')
      setLoadingMsg('')
    }
  }

  // Option 3: Top-Level Redirect flow (Full-page Fallback)
  const handleRedirectLogin = async () => {
    setLocalError(null)
    setLoadingMsg('Redirecting to LANZAR Identity...')
    try {
      const pkce = await LanzarAuth.generatePkcePair()
      const state = Math.random().toString(36).substring(2)

      sessionStorage.setItem('pkce_state', state)
      sessionStorage.setItem('pkce_code_verifier', pkce.codeVerifier)

      const authUrl = LanzarAuth.buildAuthorizeUrl({
        clientId: 'portal',
        redirectUri: window.location.origin,
        codeChallenge: pkce.codeChallenge,
        codeChallengeMethod: 'S256',
        state
      }, activeConfig)

      window.location.href = authUrl
    } catch (err) {
      console.error('[AUTH REDIRECT ERROR]', err)
      setLocalError(err.message || 'Redirect initiation failed.')
      setLoadingMsg('')
    }
  }

  // Unauthorized Access Denied / Recovery View
  if (unauthorized) {
    return (
      <div className="login-panel">
        <h2 className="login-title">{errorTitle || 'ACCESS DENIED'}</h2>
        <p className="login-desc">{errorDescription || 'You do not have customer access to this portal.'}</p>
        {(localError || globalAuthError) && <p className="error-msg">{localError || globalAuthError}</p>}
        <div className="form-actions">
          {typeof onRetry === 'function' && (
            <button type="button" id="btnRetryInit" className="primary-btn" onClick={onRetry}>
              {retryLabel}
            </button>
          )}
          {typeof handleSignOut === 'function' && (
            <button
              type="button"
              id="btnSignOutUnauthorized"
              className={typeof onRetry === 'function' ? 'text-link' : 'primary-btn'}
              onClick={handleSignOut}
            >
              SIGN OUT
            </button>
          )}
        </div>
      </div>
    )
  }

  const activeError = localError || globalAuthError

  return (
    <div className="login-panel" style={{ textAlign: 'center' }}>
      <h2 className="login-title">LANZAR PORTAL</h2>
      <p className="login-desc">Sign in with your centralized LANZAR ID to access your projects and tickets.</p>

      {activeError && <p className="error-msg">{activeError}</p>}

      <div className="auth-flow-options" style={{ marginTop: '2rem' }}>
        <button 
          type="button" 
          id="btnSignInModal"
          className="primary-btn" 
          onClick={handleModalLogin} 
          disabled={!!loadingMsg}
        >
          {loadingMsg || 'SIGN IN WITH LANZAR ID'}
        </button>

        <div className="auth-fallback-links" style={{ display: 'flex', justifyContent: 'center', gap: '1.25rem', marginTop: '1rem' }}>
          <button 
            type="button"
            id="btnSignInPopup"
            className="auth-fallback-btn"
            onClick={handlePopupLogin}
            disabled={!!loadingMsg}
            style={{ background: 'none', border: 'none', color: '#0055ff', cursor: 'pointer', fontSize: '0.85rem', textDecoration: 'underline' }}
          >
            Sign in with popup
          </button>
          <span style={{ color: '#94a3b8' }}>•</span>
          <button 
            type="button"
            id="btnSignInRedirect"
            className="auth-fallback-btn"
            onClick={handleRedirectLogin}
            disabled={!!loadingMsg}
            style={{ background: 'none', border: 'none', color: '#0055ff', cursor: 'pointer', fontSize: '0.85rem', textDecoration: 'underline' }}
          >
            Use standard redirect
          </button>
        </div>
      </div>

      {/* Embedded LANZAR ID Modal Web Component */}
      <lanzar-auth-modal 
        ref={modalRef}
        id="lanzarAuthModal"
        client-id="portal"
        redirect-uri={typeof window !== 'undefined' ? window.location.origin : ''}
      ></lanzar-auth-modal>
    </div>
  )
}
