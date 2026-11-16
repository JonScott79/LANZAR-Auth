import { useState, useEffect } from 'react'
import { onAuthStateChanged } from 'firebase/auth'
import { auth, signOutUser, signInWithCustomToken } from './firebase/auth.js'
import Login from './pages/Login.jsx'
import MyLanzarAccount from './components/MyLanzarAccount.jsx'
import { getAuthApiUrl } from './config/env.js'
import './App.css'

const ALLOWED_DOMAINS = [
  'lanzar.me',
  'localhost' // For local development testing
]

const STAGING_ALLOWED_HOSTS = new Set([
  'threadline-nova.netlify.app'
])

function isStagingHub() {
  const env = (import.meta.env.VITE_APP_ENV || '').toLowerCase()
  const host = typeof window !== 'undefined' ? window.location.hostname : ''
  return env === 'staging' || host === 'lanzar-auth-nova.netlify.app'
}

function isAllowedRedirect(uri) {
  try {
    const url = new URL(uri)
    if (ALLOWED_DOMAINS.some(domain => url.hostname === domain || url.hostname.endsWith('.' + domain))) {
      return true
    }
    if (isStagingHub()) {
      if (STAGING_ALLOWED_HOSTS.has(url.hostname.toLowerCase())) {
        return true
      }
      // Allow external customer HTTPS callbacks (and loopback) in NOVA staging;
      // backend POST /authorize authoritatively enforces exact client.redirectUris match.
      if (url.protocol === 'https:' || url.hostname === 'localhost' || url.hostname === '127.0.0.1') {
        return true
      }
    }
    return false
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

      const scopeParam = params.get('scope')
      const nonceParam = params.get('nonce')
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
          ...(scopeParam ? { scope: scopeParam } : {}),
          ...(nonceParam ? { nonce: nonceParam } : {}),
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

      await establishCentralSession(idToken)

      const targetUrl = new URL(redirectUri)
      targetUrl.searchParams.set('code', data.code)
      if (data.state) {
        targetUrl.searchParams.set('state', data.state)
      }

      // Check if executing inside an embedded iframe modal or an authentication popup
      const isIframe = typeof window !== 'undefined' && window.parent && window.parent !== window
      const isPopup = typeof window !== 'undefined' && window.opener && !window.opener.closed

      if (isIframe || isPopup) {
        const targetWindow = isIframe ? window.parent : window.opener
        const clientOrigin = targetUrl.origin

        targetWindow.postMessage({
          type: 'lanzar:authenticated',
          payload: {
            code: data.code,
            state: data.state || null
          }
        }, clientOrigin)

        if (isPopup) {
          setTimeout(() => {
            try { window.close() } catch (e) {}
          }, 300)
        }
        return
      }

      // Default top-level redirect flow
      window.location.replace(targetUrl.toString())
    } catch (e) {
      console.error('[AUTH] Failed to fetch authorization code:', e)
      setErrorMsg('Failed to securely contact identity server.')
    }
  }

  const establishCentralSession = async (idToken) => {
    try {
      await fetch(`${getAuthApiUrl()}/api/id/session/establish`, {
        method: 'POST',
        credentials: 'include',
        headers: {
          Authorization: `Bearer ${idToken}`,
          'Content-Type': 'application/json',
          'X-Lanzar-Client': 'id'
        }
      })
    } catch (_) {
      // Non-fatal: individual flow still succeeds if central cookie refresh is rejected (e.g. stale auth_time)
    }
  }

  const establishCentralAndStandaloneSession = async (firebaseUser) => {
    try {
      const tokenResult = await firebaseUser.getIdTokenResult()
      const idToken = tokenResult?.token || (await firebaseUser.getIdToken())
      const hasSessionClaim = Boolean(
        tokenResult?.claims?.session_id || tokenResult?.claims?.lanzarSessionId
      )

      await establishCentralSession(idToken)

      if (!hasSessionClaim) {
        const res = await fetch(`${getAuthApiUrl()}/api/id/session/standalone`, {
          method: 'POST',
          credentials: 'include',
          headers: {
            Authorization: `Bearer ${idToken}`,
            'Content-Type': 'application/json',
            'X-Lanzar-Client': 'id'
          }
        })
        if (res.status === 401 || res.status === 403) {
          const errData = await res.json().catch(() => ({}))
          if (errData.error === 'account_suspended' || errData.error === 'session_revoked') {
            setErrorMsg(errData.error_description || 'Your session is no longer active. Please sign in again.')
            await signOutUser()
            return { signedOut: true }
          }
        }
        if (res.ok) {
          const data = await res.json()
          const customToken = data.custom_token || data.customToken
          if (customToken) {
            await signInWithCustomToken(customToken)
            return { upgraded: true }
          }
        }
      }
    } catch (err) {
      console.warn('[AUTH] Standalone session binding notice:', err.message)
    }
    return { upgraded: false }
  }

  useEffect(() => {
    if (params.get('logout') === 'true') {
      const targetRedirect = redirectUri || 'https://lanzar.me'
      const cleanRedirect = isAllowedRedirect(targetRedirect) ? targetRedirect : 'https://lanzar.me'
      Promise.allSettled([
        fetch(`${getAuthApiUrl()}/api/id/session/logout`, {
          method: 'POST',
          credentials: 'include',
          headers: { 'X-Lanzar-Client': 'id' }
        }),
        signOutUser()
      ]).finally(() => {
        window.location.replace(cleanRedirect)
      })
      return
    }

    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      if (!firebaseUser) {
        setUser(null)
        setLoading(false)
        return
      }

      if (isOAuthFlow) {
        setUser(firebaseUser)
        setLoading(false)
        await executeAuthorizeFlow(firebaseUser)
        return
      }

      const result = await establishCentralAndStandaloneSession(firebaseUser)
      if (result.upgraded || result.signedOut) {
        return
      }

      setUser(firebaseUser)
      setLoading(false)
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
