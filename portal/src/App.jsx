import { useState, useEffect } from 'react'
import { onAuthStateChanged } from 'firebase/auth'
import { auth, signOutUser, signInWithCustomToken } from './firebase/auth.js'
import { getAuthorizedCustomer, getOrCreateAuthorizedCustomer } from './firebase/customers.js'
import { getAuthorizedAdmin } from './firebase/admins.js'

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

  // Auth Hub API URL (Local vs Prod)
  const authBackendUrl = window.location.hostname === 'localhost' ? 'http://localhost:4001' : 'https://auth-api.lanzar.me';

  useEffect(() => {
    // 1. Check if returning from Auth Hub
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const state = urlParams.get('state');

    if (code && state) {
      setIsExchanging(true);
      const storedState = sessionStorage.getItem('pkce_state');
      const codeVerifier = sessionStorage.getItem('pkce_code_verifier');

      if (state !== storedState) {
        setAuthError('Authentication state mismatch. Please try again.');
        setIsExchanging(false);
      } else {
        const cleanRedirectUri = window.location.origin;
        fetch(`${authBackendUrl}/exchange`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
              code,
              client_id: 'portal',
              redirect_uri: cleanRedirectUri,
              code_verifier: codeVerifier
          })
        })
        .then(res => res.json().then(data => ({ ok: res.ok, data })))
        .then(({ ok, data }) => {
          if (!ok) throw new Error(data.error_description || data.error || 'Failed to exchange token');
          return signInWithCustomToken(data.custom_token);
        })
        .then(() => {
          // Clean up URL
          window.history.replaceState({}, document.title, window.location.pathname);
          sessionStorage.removeItem('pkce_state');
          sessionStorage.removeItem('pkce_code_verifier');
          setIsExchanging(false);
        })
        .catch(err => {
          console.error('[AUTH] Exchange Error:', err);
          setAuthError('Failed to complete login via Auth Hub.');
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
