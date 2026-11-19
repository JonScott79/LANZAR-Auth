import { useState, useEffect } from 'react'

const CLIENT_ID = 'resume'
const AUTH_HUB_URL = import.meta.env.VITE_LANZAR_AUTH_HUB_URL || 'https://lanzar-auth-nova.netlify.app'
const AUTH_API_URL = import.meta.env.VITE_LANZAR_AUTH_API_URL || 'https://auth-api-nova.lanzar.me'
const OIDC_ISSUER = (import.meta.env.VITE_LANZAR_OIDC_ISSUER || 'https://auth.lanzar.me/nova').replace(/\/+$/, '')
const RESUME_API_URL = import.meta.env.VITE_RESUME_API_URL || 'http://localhost:3001'

function b64url(bytes) {
  let str = ''
  for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i])
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function decodeJwtPayload(tok) {
  try {
    const p = String(tok).split('.')[1].replace(/-/g, '+').replace(/_/g, '/')
    return JSON.parse(atob(p))
  } catch {
    return null
  }
}

export default function App() {
  const [session, setSession] = useState(() => {
    try {
      const raw = sessionStorage.getItem('lanzar_resume_session')
      return raw ? JSON.parse(raw) : null
    } catch {
      return null
    }
  })
  const [apiProfile, setApiProfile] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const code = params.get('code')
    const state = params.get('state')
    if (!code) return

    const storedState = sessionStorage.getItem('resume_pkce_state')
    const verifier = sessionStorage.getItem('resume_pkce_verifier')
    const storedNonce = sessionStorage.getItem('resume_pkce_nonce')
    sessionStorage.removeItem('resume_pkce_state')
    sessionStorage.removeItem('resume_pkce_verifier')
    sessionStorage.removeItem('resume_pkce_nonce')

    window.history.replaceState({}, document.title, window.location.pathname)

    if (!storedState || state !== storedState || !verifier) {
      setError('Invalid PKCE state or missing verifier.')
      return
    }

    setLoading(true)
    fetch(`${AUTH_API_URL}/oauth/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Idempotency-Key': `res_${crypto.randomUUID()}`
      },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code,
        client_id: CLIENT_ID,
        redirect_uri: window.location.origin,
        code_verifier: verifier
      })
    })
      .then((r) => r.json().then((d) => ({ ok: r.ok, d })))
      .then(({ ok, d }) => {
        if (!ok || !d.access_token) throw new Error(d.error_description || d.error || 'Token exchange failed')
        const claims = d.id_token ? decodeJwtPayload(d.id_token) : null
        if (claims) {
          const now = Math.floor(Date.now() / 1000)
          if (
            String(claims.iss || '').replace(/\/+$/, '') !== OIDC_ISSUER ||
            claims.aud !== CLIENT_ID ||
            claims.exp <= now ||
            (storedNonce && claims.nonce !== storedNonce)
          ) {
            throw new Error('OIDC id_token validation failed')
          }
        }
        const nextSession = {
          uid: claims?.sub || '',
          email: claims?.email || '',
          name: claims?.name || claims?.email || 'LANZAR User',
          accessToken: d.access_token,
          sessionId: d.session_id || null
        }
        sessionStorage.setItem('lanzar_resume_session', JSON.stringify(nextSession))
        setSession(nextSession)
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false))
  }, [])

  const handleLogin = async () => {
    const bytes = new Uint8Array(32)
    crypto.getRandomValues(bytes)
    const verifier = b64url(bytes)
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
    const challenge = b64url(new Uint8Array(digest))
    const state = crypto.randomUUID()
    const nonce = crypto.randomUUID()

    sessionStorage.setItem('resume_pkce_verifier', verifier)
    sessionStorage.setItem('resume_pkce_state', state)
    sessionStorage.setItem('resume_pkce_nonce', nonce)

    const url = new URL(AUTH_HUB_URL)
    url.searchParams.set('client_id', CLIENT_ID)
    url.searchParams.set('redirect_uri', window.location.origin)
    url.searchParams.set('code_challenge', challenge)
    url.searchParams.set('code_challenge_method', 'S256')
    url.searchParams.set('scope', 'openid profile email')
    url.searchParams.set('state', state)
    url.searchParams.set('nonce', nonce)
    window.location.assign(url.toString())
  }

  const handleVerifyApi = async () => {
    if (!session?.accessToken) return
    setError('')
    try {
      const r = await fetch(`${RESUME_API_URL}/api/me`, {
        headers: { Authorization: `Bearer ${session.accessToken}` }
      })
      const d = await r.json()
      if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`)
      setApiProfile(d)
    } catch (err) {
      setError(err.message)
    }
  }

  const handleLogout = async () => {
    if (session?.accessToken && session?.sessionId) {
      await fetch(`${AUTH_API_URL}/api/id/sessions/${encodeURIComponent(session.sessionId)}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${session.accessToken}` }
      }).catch(() => {})
    }
    sessionStorage.removeItem('lanzar_resume_session')
    setSession(null)
    setApiProfile(null)
  }

  return (
    <main style={{ maxWidth: 560, margin: '64px auto', fontFamily: 'system-ui, sans-serif', padding: 24 }}>
      <h1>LANZAR Resume</h1>
      <p>OIDC PKCE S256 Reference Integration (<code>client_id={CLIENT_ID}</code>)</p>
      {error && <p style={{ color: '#dc2626' }}>Error: {error}</p>}
      {loading && <p>Completing sign-in...</p>}
      {!session ? (
        <button type="button" onClick={handleLogin} style={{ padding: '10px 18px', fontWeight: 600 }}>
          Sign in with LANZAR ID
        </button>
      ) : (
        <div>
          <p><strong>Signed in as:</strong> {session.name} ({session.email})</p>
          <p><strong>UID:</strong> <code>{session.uid}</code></p>
          <div style={{ display: 'flex', gap: 12, marginTop: 12 }}>
            <button type="button" onClick={handleVerifyApi}>Verify /api/me</button>
            <button type="button" onClick={handleLogout}>Sign Out</button>
          </div>
          {apiProfile && <pre style={{ marginTop: 16 }}>{JSON.stringify(apiProfile, null, 2)}</pre>}
        </div>
      )}
    </main>
  )
}
