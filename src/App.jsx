import { useState, useEffect } from 'react'
import { onAuthStateChanged } from 'firebase/auth'
import { auth } from './firebase/auth.js'
import Login from './pages/Login.jsx'
import './App.css'

const ALLOWED_DOMAINS = [
  'lanzar.me',
  'localhost' // For local development testing
]

function isAllowedRedirect(uri) {
  try {
    const url = new URL(uri)
    return ALLOWED_DOMAINS.some(domain => url.hostname === domain || url.hostname.endsWith('.' + domain))
  } catch (e) {
    return false
  }
}

function App() {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)
  const [errorMsg, setErrorMsg] = useState(null)

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      setUser(firebaseUser)
      setLoading(false)
      
      if (firebaseUser) {
        const params = new URLSearchParams(window.location.search)
        let redirectUri = params.get('redirect_uri')
        const clientId = params.get('client_id')
        const state = params.get('state') || 'default_state'
        const codeChallenge = params.get('code_challenge') || 'default_challenge'
        const codeChallengeMethod = params.get('code_challenge_method') || 'S256'
        
        // If no redirect requested, default to the Portal
        if (!redirectUri) {
          redirectUri = 'https://portal.lanzar.me'
        }

        // Security check: Prevent Open Redirect vulnerabilities
        if (!isAllowedRedirect(redirectUri)) {
          console.error('[SECURITY] Blocked redirect to unauthorized domain:', redirectUri)
          setErrorMsg('Unauthorized redirect destination.')
          return
        }

        try {
            const idToken = await firebaseUser.getIdToken(true);
            
            const authBackendUrl = window.location.hostname === 'localhost' ? 'http://localhost:4001' : 'https://auth-api.lanzar.me';
            const response = await fetch(authBackendUrl + '/authorize', {
  
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    idToken,
                    client_id: clientId || 'portal',
                    redirect_uri: redirectUri,
                    state,
                    code_challenge: codeChallenge,
                    code_challenge_method: codeChallengeMethod
                })
            });

            const data = await response.json();

            if (!response.ok) {
                console.error('[AUTH] Backend authorization failed:', data);
                setErrorMsg(data.error_description || 'Authorization failed.');
                return;
            }

            // Append code and state and execute redirect seamlessly
            const targetUrl = new URL(redirectUri)
            targetUrl.searchParams.set('code', data.code)
            targetUrl.searchParams.set('state', data.state)
            window.location.replace(targetUrl.toString())
        } catch (e) {
            console.error('[AUTH] Failed to fetch authorization code:', e);
            setErrorMsg('Failed to securely contact identity server.');
        }
      }
    })
    return () => unsubscribe()
  }, [])

  if (loading) {
    return (
      <main className="loading-screen">
        <p>Connecting to LANZAR Identity...</p>
      </main>
    )
  }

  // If user is logged out, show the Login screen.
  // The Login component handles Firebase Auth. Once authenticated, the useEffect above will fire and redirect.
  return (
    <div className="portal-app">
      <div className="auth-wrapper">
        {errorMsg ? (
          <div className="login-panel" style={{ textAlign: 'center' }}>
            <h2 className="login-title">ERROR</h2>
            <p className="error-msg">{errorMsg}</p>
            <a href="https://portal.lanzar.me" className="primary-btn" style={{ textDecoration: 'none', display: 'inline-block', marginTop: '1rem' }}>GO TO PORTAL</a>
          </div>
        ) : (
          <Login />
        )}
      </div>
    </div>
  )
}

export default App
