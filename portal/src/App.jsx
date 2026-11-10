import { useState, useEffect, useRef } from 'react'
import { onAuthStateChanged } from 'firebase/auth'
import { auth, signOutUser, signInWithCustomToken } from './firebase/auth.js'
import { getOrCreateAuthorizedCustomer } from './firebase/customers.js'
import { 
  LanzarAuth, 
  DEVELOPMENT_CONFIG, 
  PRODUCTION_CONFIG 
} from './sdk/lanzar-auth-modal.js'
import {
  SESSION_STORAGE_KEY,
  SESSION_MESSAGES,
  validateSession,
  revokeCurrentSession,
  clearStoredSession,
  onSessionInvalidated,
} from './session/sessionManager.js'

import Login from './pages/Login.jsx'
import AdminApp from './admin/AdminApp.jsx'
import CustomerApp from './CustomerApp.jsx'
import './App.css'

// Re-validate the server-side session periodically and whenever the tab regains focus
const SESSION_POLL_MS = 20000

function App() {
  const [user, setUser] = useState(null)
  const [customer, setCustomer] = useState(null)
  const [admin, setAdmin] = useState(null)
  const [loading, setLoading] = useState(true)
  const [authError, setAuthError] = useState(null)
  const [isExchanging, setIsExchanging] = useState(false)
  const invalidatingRef = useRef(false)

  const activeConfig = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? DEVELOPMENT_CONFIG
    : PRODUCTION_CONFIG

  useEffect(() => {
    // 1. Check if returning from Auth Hub top-level redirect flow
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const state = urlParams.get('state');

    if (code && state) {
      // Immediately sanitize URL history synchronously to prevent double-invocation under React.StrictMode
      window.history.replaceState({}, document.title, window.location.pathname);

      setIsExchanging(true);
      const storedState = sessionStorage.getItem('pkce_state');
      const codeVerifier = sessionStorage.getItem('pkce_code_verifier');

      // Consume one-time PKCE state and verifier immediately
      sessionStorage.removeItem('pkce_state');
      sessionStorage.removeItem('pkce_code_verifier');

      if (!storedState || state !== storedState) {
        setAuthError('Authentication state mismatch. Please try again.');
        setIsExchanging(false);
      } else if (!codeVerifier) {
        setAuthError('Missing PKCE verifier for authorization exchange.');
        setIsExchanging(false);
      } else {
        const cleanRedirectUri = window.location.origin;
        LanzarAuth.exchangeCodeForSession({
          code,
          clientId: 'portal',
          redirectUri: cleanRedirectUri,
          codeVerifier
        }, activeConfig)
        .then((data) => {
          if (data.session_id) {
            sessionStorage.setItem(SESSION_STORAGE_KEY, data.session_id);
          }
          return signInWithCustomToken(data.custom_token);
        })
        .then(() => {
          setIsExchanging(false);
        })
        .catch((err) => {
          console.error('[AUTH] Exchange Error:', err);
          setAuthError(err.message || 'Failed to complete login via Auth Hub.');
          setIsExchanging(false);
        });
      }
    }

    // 2. Normal auth state listener (always registered, including after a redirect callback)
    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      if (firebaseUser) {
        setUser(firebaseUser)
        setAuthError(null)
        try {
          // Server-side validation of the LANZAR ID session; administrator status is
          // resolved by the trusted backend, never from client-side claims or email checks.
          const session = await validateSession()

          if (session.status === 'unavailable') {
            // Fail closed without destroying the session: grant nothing until verified
            setCustomer(null)
            setAdmin(null)
            setAuthError(SESSION_MESSAGES.unavailable)
          } else if (session.status !== 'valid') {
            await invalidateSession(session.status)
          } else {
            sessionStorage.setItem(SESSION_STORAGE_KEY, session.session_id)

            if (session.is_admin === true) {
              setAdmin({
                role: 'ADMIN',
                active: true,
                uid: session.uid,
                email: session.email,
                displayName: session.display_name || firebaseUser.displayName || session.email,
              })
              setCustomer(null)
            } else {
              const customerData = await getOrCreateAuthorizedCustomer(firebaseUser)
              setAdmin(null)
              setCustomer(customerData || null)
              if (!customerData) {
                setAuthError('Access Denied: This account is inactive or is not a recognized customer.')
              }
            }
          }
        } catch (error) {
          console.error('[AUTH ERROR] Error fetching user roles:', error)
          setCustomer(null)
          setAdmin(null)
          setAuthError('Failed to verify account permissions.')
        }
      } else {
        setUser(null)
        setCustomer(null)
        setAdmin(null)
      }
      setLoading(false)
    })
    return () => unsubscribe()
  }, [])

  // Clears Portal auth state and returns the user to login with an explanatory message
  async function invalidateSession(reason) {
    if (invalidatingRef.current) return
    invalidatingRef.current = true
    try {
      clearStoredSession()
      try { await signOutUser() } catch (_) { /* already signed out */ }
      setUser(null)
      setCustomer(null)
      setAdmin(null)
      setAuthError(SESSION_MESSAGES[reason] || SESSION_MESSAGES.invalid)
      setLoading(false)
    } finally {
      invalidatingRef.current = false
    }
  }

  // Session revocation / expiry detection while signed in
  useEffect(() => {
    if (!user) return undefined

    let cancelled = false
    const check = async () => {
      const session = await validateSession()
      if (cancelled || session.status === 'unavailable' || session.status === 'valid') return
      await invalidateSession(session.status)
    }

    const interval = setInterval(check, SESSION_POLL_MS)
    const onVisible = () => { if (document.visibilityState === 'visible') check() }
    window.addEventListener('focus', check)
    document.addEventListener('visibilitychange', onVisible)

    // Backend API calls that come back 401 (revoked/expired) also end the session immediately
    const offInvalidated = onSessionInvalidated((reason) => { if (!cancelled) invalidateSession(reason) })

    return () => {
      cancelled = true
      clearInterval(interval)
      window.removeEventListener('focus', check)
      document.removeEventListener('visibilitychange', onVisible)
      offInvalidated()
    }
  }, [user])

  const handleSignOut = async () => {
    setLoading(true)
    // Revoke the LANZAR ID session server-side first (needs the ID token), then end Firebase auth
    await revokeCurrentSession()
    await signOutUser()
    clearStoredSession()
    setLoading(false)
    const authHubUrl = window.location.hostname === 'localhost' ? 'http://localhost:4000' : 'https://auth.lanzar.me';
    window.location.href = `${authHubUrl}?logout=true&redirect_uri=${encodeURIComponent(window.location.origin)}`;
  }

  if (loading || isExchanging) {
    return (
      <main className="loading-screen">
        <p>{isExchanging ? 'Completing secure login...' : 'Connecting to LANZAR launching facility...'}</p>
      </main>
    )
  }

  if (!user) {
    return (
      <div className="portal-app">
        <div className="portal-container" style={{ alignItems: 'center', justifyContent: 'center' }}>
          <Login authError={authError} />
        </div>
      </div>
    )
  }

  if (authError && !admin && !customer) {
    return (
      <div className="portal-app">
        <div className="portal-container" style={{ alignItems: 'center', justifyContent: 'center' }}>
          <Login authError={authError} unauthorized={true} handleSignOut={handleSignOut} />
        </div>
      </div>
    )
  }

  if (admin) {
    return <AdminApp admin={admin} user={user} handleSignOut={handleSignOut} />
  }

  if (customer) {
    return <CustomerApp customer={customer} user={user} handleSignOut={handleSignOut} />
  }

  return (
    <div className="portal-app">
      <div className="portal-container" style={{ alignItems: 'center', justifyContent: 'center' }}>
        <Login authError={authError || 'Access Denied: Account is neither an active administrator nor a recognized customer.'} unauthorized={true} handleSignOut={handleSignOut} />
      </div>
    </div>
  )
}

export default App
