import { useState, useEffect, useRef, useCallback } from 'react'
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
import { withTimeout } from './utils/asyncTimeout.js'

import Login from './pages/Login.jsx'
import AdminApp from './admin/AdminApp.jsx'
import CustomerApp from './CustomerApp.jsx'
import './App.css'

// Re-validate the server-side session periodically and whenever the tab regains focus
const SESSION_POLL_MS = 20000
const INIT_STEP_TIMEOUT_MS = 15000
const BOOTSTRAP_TIMEOUT_MS = 15000

const INIT_STAGE_LABELS = {
  oauth_exchange: 'Completing secure login...',
  firebase_signin: 'Establishing Portal credentials...',
  session_validate: 'Validating LANZAR ID session and permissions...',
  profile_resolve: 'Loading LANZAR launching facility profile...',
  auth_bootstrap: 'Connecting to LANZAR launching facility...',
}

function App() {
  const [user, setUser] = useState(null)
  const [customer, setCustomer] = useState(null)
  const [admin, setAdmin] = useState(null)
  const [loading, setLoading] = useState(true)
  const [authError, setAuthError] = useState(null)
  const [isExchanging, setIsExchanging] = useState(false)
  const [initStage, setInitStage] = useState('auth_bootstrap')
  const [initFailure, setInitFailure] = useState(null)

  const invalidatingRef = useRef(false)
  const exchangingRef = useRef(false)
  const mountedRef = useRef(true)
  const bootstrapSettledRef = useRef(false)
  const resolvedUidRef = useRef(null)
  const attemptIdRef = useRef(0)
  const activeResolutionRef = useRef({ uid: null, promise: null })

  const activeConfig = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? DEVELOPMENT_CONFIG
    : PRODUCTION_CONFIG

  // Clears Portal auth state and returns the user to login with an explanatory message
  const invalidateSession = useCallback(async (reason) => {
    if (invalidatingRef.current) return
    invalidatingRef.current = true
    try {
      clearStoredSession()
      try { await signOutUser() } catch (_) { /* already signed out */ }
      if (!mountedRef.current) return
      resolvedUidRef.current = null
      setUser(null)
      setCustomer(null)
      setAdmin(null)
      setInitFailure(null)
      setAuthError(SESSION_MESSAGES[reason] || SESSION_MESSAGES.invalid)
      setLoading(false)
    } finally {
      invalidatingRef.current = false
    }
  }, [])

  // Single-flight, timeout-bounded session validation and Portal workspace resolution
  const resolveUserSession = useCallback(async (firebaseUser) => {
    if (!firebaseUser?.uid) return

    if (
      activeResolutionRef.current.uid === firebaseUser.uid &&
      activeResolutionRef.current.promise
    ) {
      return activeResolutionRef.current.promise
    }

    const attemptId = ++attemptIdRef.current
    const runPromise = (async () => {
      if (resolvedUidRef.current !== firebaseUser.uid) {
        setLoading(true)
      }
      setUser(firebaseUser)
      setAuthError(null)
      setInitFailure(null)
      setInitStage('session_validate')
      console.info('[PORTAL INIT] Stage: session_validate')

      try {
        // Server-side validation of the LANZAR ID session; administrator status is
        // resolved by the trusted backend, never from client-side claims or email checks.
        const session = await validateSession({ timeoutMs: INIT_STEP_TIMEOUT_MS })
        if (!mountedRef.current || attemptIdRef.current !== attemptId) return

        if (session.status === 'unavailable') {
          // Fail closed without destroying the session: grant nothing until verified
          const msg = session.error || SESSION_MESSAGES.unavailable
          resolvedUidRef.current = null
          setCustomer(null)
          setAdmin(null)
          setAuthError(msg)
          setInitFailure({ stage: 'session_validate', message: msg, canRetrySession: true })
          return
        }

        if (session.status !== 'valid') {
          await invalidateSession(session.status)
          return
        }

        sessionStorage.setItem(SESSION_STORAGE_KEY, session.session_id)

        if (session.is_admin === true) {
          resolvedUidRef.current = firebaseUser.uid
          setAdmin({
            role: 'ADMIN',
            active: true,
            uid: session.uid,
            email: session.email,
            displayName: session.display_name || firebaseUser.displayName || session.email,
          })
          setCustomer(null)
          setInitFailure(null)
          console.info('[PORTAL INIT] Stage: ready (admin)')
          return
        }

        setInitStage('profile_resolve')
        console.info('[PORTAL INIT] Stage: profile_resolve')
        const customerData = await getOrCreateAuthorizedCustomer(firebaseUser, {
          timeoutMs: INIT_STEP_TIMEOUT_MS,
        })
        if (!mountedRef.current || attemptIdRef.current !== attemptId) return

        setAdmin(null)
        setCustomer(customerData || null)
        setInitFailure(null)
        if (customerData) {
          resolvedUidRef.current = firebaseUser.uid
          console.info('[PORTAL INIT] Stage: ready (customer)')
        } else {
          resolvedUidRef.current = null
          setAuthError('Access Denied: This account is inactive or is not a recognized customer.')
          console.warn('[PORTAL INIT] Stage: denied (inactive or unrecognized customer)')
        }
      } catch (error) {
        if (!mountedRef.current || attemptIdRef.current !== attemptId) return
        const failedStage = error?.stage || 'session_validate'
        const failureMsg = error?.message || 'Failed to verify account permissions.'
        console.error(`[PORTAL INIT] Failed at stage "${failedStage}":`, failureMsg)
        resolvedUidRef.current = null
        setCustomer(null)
        setAdmin(null)
        setAuthError(failureMsg)
        setInitFailure({
          stage: failedStage,
          message: failureMsg,
          canRetrySession: true,
        })
      } finally {
        if (activeResolutionRef.current.promise === runPromise) {
          activeResolutionRef.current = { uid: null, promise: null }
        }
        if (mountedRef.current && attemptIdRef.current === attemptId) {
          setLoading(false)
        }
      }
    })()

    activeResolutionRef.current = { uid: firebaseUser.uid, promise: runPromise }
    return runPromise
  }, [invalidateSession])

  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
    }
  }, [])

  useEffect(() => {
    // 1. Check if returning from Auth Hub top-level redirect flow
    const urlParams = new URLSearchParams(window.location.search);
    const oauthError = urlParams.get('error');
    const oauthErrorDescription = urlParams.get('error_description');
    const code = urlParams.get('code');
    const state = urlParams.get('state');

    if (oauthError) {
      window.history.replaceState({}, document.title, window.location.pathname);
      sessionStorage.removeItem('pkce_state');
      sessionStorage.removeItem('pkce_code_verifier');
      setAuthError(oauthErrorDescription || `Authentication failed at LANZAR ID (${oauthError}).`);
      exchangingRef.current = false;
      setIsExchanging(false);
    } else if (code && state) {
      // Immediately sanitize URL history synchronously to prevent double-invocation under React.StrictMode
      window.history.replaceState({}, document.title, window.location.pathname);

      exchangingRef.current = true;
      setIsExchanging(true);
      setInitStage('oauth_exchange');
      setInitFailure(null);
      console.info('[PORTAL INIT] Stage: oauth_exchange');

      const storedState = sessionStorage.getItem('pkce_state');
      const codeVerifier = sessionStorage.getItem('pkce_code_verifier');

      // Consume one-time PKCE state and verifier immediately
      sessionStorage.removeItem('pkce_state');
      sessionStorage.removeItem('pkce_code_verifier');

      if (!storedState || state !== storedState) {
        setAuthError('Authentication state mismatch. Please try again.');
        exchangingRef.current = false;
        setIsExchanging(false);
        setLoading(false);
      } else if (!codeVerifier) {
        setAuthError('Missing PKCE verifier for authorization exchange.');
        exchangingRef.current = false;
        setIsExchanging(false);
        setLoading(false);
      } else {
        const cleanRedirectUri = window.location.origin;
        LanzarAuth.exchangeCodeForSession({
          code,
          clientId: 'portal',
          redirectUri: cleanRedirectUri,
          codeVerifier,
          timeoutMs: INIT_STEP_TIMEOUT_MS,
        }, activeConfig)
        .then(async (data) => {
          if (data.session_id) {
            sessionStorage.setItem(SESSION_STORAGE_KEY, data.session_id);
          }
          if (!mountedRef.current) return;
          setInitStage('firebase_signin');
          console.info('[PORTAL INIT] Stage: firebase_signin');
          await withTimeout(
            signInWithCustomToken(data.custom_token),
            INIT_STEP_TIMEOUT_MS,
            'Timed out establishing Firebase credentials. Please try again.',
            'firebase_signin'
          );
          if (!mountedRef.current) return;
          if (auth.currentUser) {
            exchangingRef.current = false;
            setIsExchanging(false);
            await resolveUserSession(auth.currentUser);
          }
        })
        .catch((err) => {
          console.error('[PORTAL INIT] Failed at stage "oauth_exchange":', err?.message || err);
          if (!mountedRef.current) return;
          setAuthError(err?.message || 'Failed to complete login via Auth Hub.');
          setLoading(false);
        })
        .finally(() => {
          exchangingRef.current = false;
          if (mountedRef.current) {
            setIsExchanging(false);
            if (!auth.currentUser && !activeResolutionRef.current.promise) {
              setLoading(false);
            }
          }
        });
      }
    }

    // Watchdog so Portal never hangs indefinitely if Firebase Auth bootstrap fails to emit
    const bootstrapTimer = setTimeout(() => {
      if (!mountedRef.current || bootstrapSettledRef.current || exchangingRef.current) return;
      console.error('[PORTAL INIT] Failed at stage "auth_bootstrap": Authentication initialization timed out');
      setInitFailure({
        stage: 'auth_bootstrap',
        message: 'Portal initialization timed out while connecting to authentication services.',
        canRetrySession: false,
      });
      setLoading(false);
    }, BOOTSTRAP_TIMEOUT_MS);

    // 2. Normal auth state listener (always registered, including after a redirect callback)
    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      bootstrapSettledRef.current = true;
      clearTimeout(bootstrapTimer);
      if (!mountedRef.current) return;

      if (firebaseUser) {
        await resolveUserSession(firebaseUser);
      } else {
        resolvedUidRef.current = null;
        setUser(null);
        setCustomer(null);
        setAdmin(null);
        if (!exchangingRef.current) {
          setLoading(false);
        }
      }
    });

    return () => {
      clearTimeout(bootstrapTimer);
      unsubscribe();
    };
  }, [activeConfig, resolveUserSession])

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
  }, [user, invalidateSession])

  const handleRetryInit = useCallback(async () => {
    setInitFailure(null)
    setAuthError(null)
    if (auth.currentUser) {
      await resolveUserSession(auth.currentUser)
    } else {
      setLoading(false)
    }
  }, [resolveUserSession])

  const handleSignOut = async () => {
    setLoading(true)
    setInitFailure(null)
    resolvedUidRef.current = null
    // Revoke the LANZAR ID session server-side first (needs the ID token), then end Firebase auth
    await revokeCurrentSession()
    await signOutUser()
    clearStoredSession()
    setLoading(false)
    const authHubUrl = window.location.hostname === 'localhost' ? 'http://localhost:4000' : 'https://auth.lanzar.me';
    window.location.href = `${authHubUrl}?logout=true&redirect_uri=${encodeURIComponent(window.location.origin)}`;
  }

  if (loading || isExchanging) {
    const label = INIT_STAGE_LABELS[initStage] || INIT_STAGE_LABELS.auth_bootstrap
    return (
      <main className="loading-screen" data-init-stage={initStage}>
        <p>{label}</p>
      </main>
    )
  }

  if (initFailure && !admin && !customer) {
    return (
      <div className="portal-app">
        <div className="portal-container" style={{ alignItems: 'center', justifyContent: 'center' }}>
          <Login
            authError={initFailure.message}
            unauthorized={true}
            errorTitle="CONNECTION ISSUE"
            errorDescription={`Portal initialization stopped during ${initFailure.stage.replace('_', ' ')}.`}
            onRetry={handleRetryInit}
            retryLabel="RETRY"
            handleSignOut={user ? handleSignOut : undefined}
          />
        </div>
      </div>
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
