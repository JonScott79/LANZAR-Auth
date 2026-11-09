import { useState, useEffect } from 'react'
import { onAuthStateChanged } from 'firebase/auth'
import { auth, signOutUser } from './firebase/auth.js'
import Login from './pages/Login.jsx'
import MyLanzarAccount from './components/MyLanzarAccount.jsx'
import { getAuthApiUrl } from './config/env.js'
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
  const [mfaChallenge, setMfaChallenge] = useState(null)

  const params = new URLSearchParams(window.location.search)
  const clientId = params.get('client_id')
  const redirectUri = params.get('redirect_uri')
  const forceAccountView = params.get('view') === 'account' || window.location.pathname.startsWith('/account')
  const isOAuthFlow = Boolean(clientId && redirectUri && !forceAccountView)

  const executeAuthorizeFlow = async (firebaseUser, mfaProof = null) => {
    if (!isOAuthFlow) {
      // In standalone account management mode, no OAuth redirect is needed
      return
    }

    const state = params.get('state') || ''
    const codeChallenge = params.get('code_challenge')
    const codeChallengeMethod = params.get('code_challenge_method')

    // Strict PKCE verification at client boundary
    if (!codeChallenge) {
      console.error('[SECURITY] Missing required PKCE code_challenge')
      setErrorMsg('Invalid OAuth Request: PKCE code_challenge parameter is required.')
      return
    }

    if (codeChallengeMethod !== 'S256') {
      console.error('[SECURITY] Invalid or unsupported PKCE code_challenge_method:', codeChallengeMethod)
      setErrorMsg('Invalid OAuth Request: code_challenge_method must be explicitly S256.')
      return
    }

    if (!isAllowedRedirect(redirectUri)) {
      console.error('[SECURITY] Blocked redirect to unauthorized domain:', redirectUri)
      setErrorMsg('Unauthorized redirect destination.')
      return
    }

    const cleanRedirectUri = redirectUri.replace(/\/+$/, '') || redirectUri

    try {
      const idToken = await firebaseUser.getIdToken(true)
      const authBackendUrl = getAuthApiUrl()

      const response = await fetch(authBackendUrl + '/authorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          idToken,
          client_id: clientId,
          redirect_uri: cleanRedirectUri,
          state,
          code_challenge: codeChallenge,
          code_challenge_method: codeChallengeMethod,
          mfa_proof: mfaProof
        })
      })

      const data = await response.json()

      if (response.status === 403 && data.mfa_required) {
        setMfaChallenge({
          required: true,
          enrollmentRequired: Boolean(data.enrollment_required),
          mfaSession: data.mfa_session,
          methods: data.methods || ['totp'],
          user: firebaseUser
        })
        return
      }

      if (!response.ok) {
        console.error('[AUTH] Backend authorization failed:', data)
        setErrorMsg(data.error_description || 'Authorization failed.')
        return
      }

      const targetUrl = new URL(redirectUri)
      targetUrl.searchParams.set('code', data.code)
      if (data.state) {
        targetUrl.searchParams.set('state', data.state)
      }
      window.location.replace(targetUrl.toString())
    } catch (e) {
      console.error('[AUTH] Failed to fetch authorization code:', e)
      setErrorMsg('Failed to securely contact identity server.')
    }
  }

  useEffect(() => {
    if (params.get('logout') === 'true') {
      const targetRedirect = redirectUri || 'https://lanzar.me'
      const cleanRedirect = isAllowedRedirect(targetRedirect) ? targetRedirect : 'https://lanzar.me'
      signOutUser().finally(() => {
        window.location.replace(cleanRedirect)
      })
      return
    }

    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      setUser(firebaseUser)
      setLoading(false)

      if (firebaseUser && isOAuthFlow) {
        await executeAuthorizeFlow(firebaseUser)
      }
    })
    return () => unsubscribe()
  }, [])

  if (loading) {
    return (
      <main className="loading-screen">
        <div className="lanzar-spinner" style={{ width: 40, height: 40, margin: '0 auto 1rem auto' }}></div>
        <p>Connecting to LANZAR Identity Core...</p>
      </main>
    )
  }

  return (
    <div className="portal-app">
      <div className="auth-wrapper" style={{ maxWidth: user && !isOAuthFlow ? '940px' : '440px' }}>
        {errorMsg ? (
          <div className="login-panel" style={{ textAlign: 'center' }}>
            <h2 className="login-title">AUTHENTICATION ALERT</h2>
            <p className="error-msg">{errorMsg}</p>
            <a href="https://lanzar.me" className="primary-btn" style={{ textDecoration: 'none', display: 'inline-block', marginTop: '1rem' }}>
              RETURN TO LANZAR.ME
            </a>
          </div>
        ) : user && !isOAuthFlow ? (
          /* User is logged into LANZAR Central Account Portal */
          <MyLanzarAccount user={user} />
        ) : (
          /* User is logging in or in OAuth PKCE redirect flow */
          <Login 
            mfaChallenge={mfaChallenge}
            onMfaVerified={(proof) => {
              if (user) {
                executeAuthorizeFlow(user, proof)
              }
            }}
          />
        )}
      </div>
    </div>
  )
}

export default App
