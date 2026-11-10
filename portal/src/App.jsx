import { useState, useEffect } from 'react'
import { onAuthStateChanged } from 'firebase/auth'
import { auth, signOutUser, signInWithCustomToken } from './firebase/auth.js'
import { getAuthorizedCustomer, getOrCreateAuthorizedCustomer } from './firebase/customers.js'
import { getAuthorizedAdmin } from './firebase/admins.js'
import { 
  LanzarAuth, 
  DEVELOPMENT_CONFIG, 
  PRODUCTION_CONFIG 
} from './sdk/lanzar-auth-modal.js'

import Login from './pages/Login.jsx'
import AdminApp from './admin/AdminApp.jsx'
import CustomerApp from './CustomerApp.jsx'
import './App.css'

function App() {
  const [user, setUser] = useState(null)
  const [customer, setCustomer] = useState(null)
  const [admin, setAdmin] = useState(null)
  const [loading, setLoading] = useState(true)
  const [authError, setAuthError] = useState(null)
  const [isExchanging, setIsExchanging] = useState(false)

  const activeConfig = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? DEVELOPMENT_CONFIG
    : PRODUCTION_CONFIG

  useEffect(() => {
    // 1. Check if returning from Auth Hub top-level redirect flow
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const state = urlParams.get('state');

    if (code && state) {
      setIsExchanging(true);
      const storedState = sessionStorage.getItem('pkce_state');
      const codeVerifier = sessionStorage.getItem('pkce_code_verifier');

      if (!storedState || state !== storedState) {
        setAuthError('Authentication state mismatch. Please try again.');
        setIsExchanging(false);
        window.history.replaceState({}, document.title, window.location.pathname);
      } else if (!codeVerifier) {
        setAuthError('Missing PKCE verifier for authorization exchange.');
        setIsExchanging(false);
        window.history.replaceState({}, document.title, window.location.pathname);
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
            sessionStorage.setItem('lanzar_session_id', data.session_id);
          }
          return signInWithCustomToken(data.custom_token);
        })
        .then(() => {
          window.history.replaceState({}, document.title, window.location.pathname);
          sessionStorage.removeItem('pkce_state');
          sessionStorage.removeItem('pkce_code_verifier');
          setIsExchanging(false);
        })
        .catch((err) => {
          console.error('[AUTH] Exchange Error:', err);
          setAuthError(err.message || 'Failed to complete login via Auth Hub.');
          setIsExchanging(false);
          window.history.replaceState({}, document.title, window.location.pathname);
        });
        return; // Don't process onAuthStateChanged immediately, let it trigger after custom token
      }
    }

    // 2. Normal auth state listener
    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      if (firebaseUser) {
        setUser(firebaseUser)
        setAuthError(null)
        try {
          const authorizedAdmin = await getAuthorizedAdmin(firebaseUser.uid, firebaseUser.email)
          
          if (authorizedAdmin) {
            setAdmin(authorizedAdmin)
            setCustomer(null)
          } else {
            const customerData = await getOrCreateAuthorizedCustomer(firebaseUser)
            if (customerData) {
              setCustomer(customerData)
              setAdmin(null)
            } else {
              setCustomer(null)
              setAdmin(null)
            }
          }
        } catch (error) {
          console.error('[AUTH ERROR] Error fetching user roles:', error)
          setAuthError('Failed to verify account permissions.')
        }
      } else {
        const urlParams = new URLSearchParams(window.location.search);
        if ((window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') && 
            (window.location.pathname.startsWith('/admin') || urlParams.get('preview') === 'admin')) {
          setUser({
            uid: 'Tcdyrq9vIVhfPeeDPnTrZIP553x1',
            email: 'jon@lanzar.me',
            displayName: 'Jon Scott',
            getIdToken: async () => 'mock_admin_dev_token'
          });
          setAdmin({ role: 'ADMIN', active: true, email: 'jon@lanzar.me' });
          setCustomer(null);
        } else {
          setUser(null);
          setCustomer(null);
          setAdmin(null);
        }
      }
      setLoading(false)
    })
    return () => unsubscribe()
  }, [])

  const handleSignOut = async () => {
    setLoading(true)
    await signOutUser()
    sessionStorage.removeItem('pkce_state')
    sessionStorage.removeItem('pkce_code_verifier')
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
