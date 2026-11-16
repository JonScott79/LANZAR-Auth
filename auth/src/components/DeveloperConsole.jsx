import { useState, useEffect, useCallback } from 'react'
import { getAuthApiUrl } from '../config/env.js'

export default function DeveloperConsole({ user, notify }) {
  const authBackendUrl = getAuthApiUrl()
  const [loading, setLoading] = useState(true)
  const [tenants, setTenants] = useState([])
  const [selectedTenantId, setSelectedTenantId] = useState('')
  const [tenantDetail, setTenantDetail] = useState(null)
  const [discovery, setDiscovery] = useState(null)
  const [clients, setClients] = useState([])
  const [billing, setBilling] = useState(null)
  const [auditLogs, setAuditLogs] = useState([])

  // Create Tenant Form
  const [orgName, setOrgName] = useState('')
  const [orgSlug, setOrgSlug] = useState('')
  const [creatingOrg, setCreatingOrg] = useState(false)

  // Create App Form
  const [appName, setAppName] = useState('')
  const [appClientId, setAppClientId] = useState('')
  const [appRedirectUris, setAppRedirectUris] = useState('https://localhost:5173/callback')
  const [appAllowedOrigins, setAppAllowedOrigins] = useState('https://localhost:5173')
  const [appAuthMethod, setAppAuthMethod] = useState('none')
  const [creatingApp, setCreatingApp] = useState(false)
  const [revealedSecret, setRevealedSecret] = useState(null)

  const authFetch = useCallback(async (path, options = {}) => {
    const idToken = await user.getIdToken()
    const res = await fetch(`${authBackendUrl}${path}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${idToken}`,
        ...(options.headers || {})
      }
    })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) {
      throw new Error(data.error_description || data.error || `HTTP ${res.status}`)
    }
    return data
  }, [authBackendUrl, user])

  const loadTenants = useCallback(async () => {
    setLoading(true)
    try {
      const data = await authFetch('/api/dev/tenants')
      const list = Array.isArray(data.tenants) ? data.tenants : []
      setTenants(list)
      if (list.length > 0 && !selectedTenantId) {
        setSelectedTenantId(list[0].tenantId)
      }
    } catch (err) {
      notify(err.message || 'Failed to load developer organizations', 'error')
    } finally {
      setLoading(false)
    }
  }, [authFetch, notify, selectedTenantId])

  const loadTenantWorkspace = useCallback(async (tid) => {
    if (!tid) return
    try {
      const [detailRes, clientsRes, billingRes, logsRes] = await Promise.all([
        authFetch(`/api/dev/tenants/${tid}`),
        authFetch(`/api/dev/tenants/${tid}/clients`),
        authFetch(`/api/dev/tenants/${tid}/billing`),
        authFetch(`/api/dev/tenants/${tid}/audit-logs?limit=15`)
      ])
      setTenantDetail(detailRes.tenant)
      setDiscovery(detailRes.discovery)
      setClients(clientsRes.clients || [])
      setBilling(billingRes)
      setAuditLogs(logsRes.logs || [])
    } catch (err) {
      notify(err.message || 'Failed to load tenant workspace', 'error')
    }
  }, [authFetch, notify])

  useEffect(() => {
    loadTenants()
  }, [loadTenants])

  useEffect(() => {
    if (selectedTenantId) {
      loadTenantWorkspace(selectedTenantId)
    }
  }, [selectedTenantId, loadTenantWorkspace])

  const handleCreateTenant = async (e) => {
    e.preventDefault()
    if (!orgName.trim()) return
    setCreatingOrg(true)
    try {
      const data = await authFetch('/api/dev/tenants', {
        method: 'POST',
        body: JSON.stringify({
          name: orgName.trim(),
          tenantId: orgSlug.trim() || undefined
        })
      })
      setOrgName('')
      setOrgSlug('')
      notify(`Organization "${data.tenant.name}" created!`, 'success')
      await loadTenants()
      setSelectedTenantId(data.tenant.tenantId)
    } catch (err) {
      notify(err.message, 'error')
    } finally {
      setCreatingOrg(false)
    }
  }

  const handleCreateClient = async (e) => {
    e.preventDefault()
    if (!selectedTenantId || !appName.trim()) return
    setCreatingApp(true)
    setRevealedSecret(null)
    try {
      const redirectUris = appRedirectUris.split(/[\n,]+/).map(s => s.trim()).filter(Boolean)
      const allowedOrigins = appAllowedOrigins.split(/[\n,]+/).map(s => s.trim()).filter(Boolean)
      const data = await authFetch(`/api/dev/tenants/${selectedTenantId}/clients`, {
        method: 'POST',
        body: JSON.stringify({
          name: appName.trim(),
          clientId: appClientId.trim() || undefined,
          redirectUris,
          allowedOrigins,
          allowedScopes: ['openid', 'profile', 'email'],
          tokenEndpointAuthMethod: appAuthMethod
        })
      })
      setAppName('')
      setAppClientId('')
      if (data.clientSecret) {
        setRevealedSecret({ clientId: data.client.clientId, clientSecret: data.clientSecret })
      }
      notify(`Application "${data.client.clientId}" registered!`, 'success')
      await loadTenantWorkspace(selectedTenantId)
    } catch (err) {
      notify(err.message, 'error')
    } finally {
      setCreatingApp(false)
    }
  }

  const handleRotateSecret = async (clientId) => {
    try {
      const data = await authFetch(`/api/dev/tenants/${selectedTenantId}/clients/${clientId}/rotate-secret`, {
        method: 'POST'
      })
      setRevealedSecret({ clientId: data.clientId, clientSecret: data.clientSecret })
      notify(`Client secret rotated for ${clientId}. Save it now — it will not be shown again.`, 'info')
    } catch (err) {
      notify(err.message, 'error')
    }
  }

  const handleToggleClient = async (client) => {
    try {
      await authFetch(`/api/dev/tenants/${selectedTenantId}/clients/${client.clientId}`, {
        method: 'PATCH',
        body: JSON.stringify({ enabled: !client.enabled })
      })
      notify(`Application ${client.clientId} ${client.enabled ? 'disabled' : 'enabled'}.`, 'info')
      await loadTenantWorkspace(selectedTenantId)
    } catch (err) {
      notify(err.message, 'error')
    }
  }

  const handleUpgrade = async (planId) => {
    try {
      const currentUrl = window.location.href.split('#')[0]
      const data = await authFetch(`/api/dev/tenants/${selectedTenantId}/billing/checkout`, {
        method: 'POST',
        body: JSON.stringify({
          planId,
          successUrl: currentUrl,
          cancelUrl: currentUrl
        })
      })
      if (data.url) {
        window.location.href = data.url
      }
    } catch (err) {
      notify(err.message, 'error')
    }
  }

  if (loading) {
    return <div className="tab-pane"><p>Loading Developer Console...</p></div>
  }

  return (
    <div className="tab-pane developer-console-pane">
      <div className="profile-form-card">
        <h4 className="section-title">ORGANIZATION &amp; TENANT WORKSPACE</h4>
        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', alignItems: 'center', marginBottom: '16px' }}>
          {tenants.length > 0 && (
            <select
              className="form-input"
              style={{ maxWidth: '280px' }}
              value={selectedTenantId}
              onChange={(e) => setSelectedTenantId(e.target.value)}
            >
              {tenants.map((t) => (
                <option key={t.tenantId} value={t.tenantId}>
                  {t.name} ({t.tenantId}) — {t.plan}
                </option>
              ))}
            </select>
          )}
          <form onSubmit={handleCreateTenant} style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', flex: 1 }}>
            <input
              type="text"
              className="form-input"
              placeholder="New Organization Name (e.g. Acme SaaS)"
              value={orgName}
              onChange={(e) => setOrgName(e.target.value)}
              required
              style={{ maxWidth: '240px' }}
            />
            <input
              type="text"
              className="form-input"
              placeholder="Slug (optional, e.g. acme-saas)"
              value={orgSlug}
              onChange={(e) => setOrgSlug(e.target.value)}
              style={{ maxWidth: '200px' }}
            />
            <button type="submit" className="btn-primary-deck" disabled={creatingOrg}>
              {creatingOrg ? 'CREATING...' : '+ CREATE TENANT'}
            </button>
          </form>
        </div>

        {tenantDetail && discovery && (
          <div style={{ fontSize: '12px', background: 'rgba(15, 23, 42, 0.6)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(148,163,184,0.2)' }}>
            <div><strong>Tenant ID:</strong> <code>{tenantDetail.tenantId}</code> | <strong>Plan:</strong> <code>{tenantDetail.plan}</code> | <strong>Apps:</strong> {billing?.usage?.appsUsed ?? clients.length} / {billing?.usage?.maxApps ?? 3}</div>
            <div><strong>OIDC Issuer:</strong> <code>{discovery.issuer}</code></div>
            <div><strong>JWKS URI:</strong> <code>{discovery.jwks_uri}</code></div>
            <div><strong>Token Endpoint:</strong> <code>{discovery.token_endpoint}</code></div>
          </div>
        )}
      </div>

      {selectedTenantId && (
        <>
          <div className="profile-form-card" style={{ marginTop: '16px' }}>
            <h4 className="section-title">REGISTER OAUTH APPLICATION</h4>
            <form onSubmit={handleCreateClient} className="deck-form">
              <div className="form-group">
                <label className="form-label">APPLICATION NAME</label>
                <input type="text" className="form-input" value={appName} onChange={(e) => setAppName(e.target.value)} placeholder="My SaaS Web App" required />
              </div>
              <div className="form-group">
                <label className="form-label">CLIENT ID (OPTIONAL SLUG)</label>
                <input type="text" className="form-input" value={appClientId} onChange={(e) => setAppClientId(e.target.value)} placeholder="auto-generated if blank" />
              </div>
              <div className="form-group">
                <label className="form-label">REDIRECT URIS (COMMA OR NEWLINE SEPARATED)</label>
                <input type="text" className="form-input" value={appRedirectUris} onChange={(e) => setAppRedirectUris(e.target.value)} required />
              </div>
              <div className="form-group">
                <label className="form-label">ALLOWED CORS ORIGINS (EXACT ORIGIN URLS)</label>
                <input type="text" className="form-input" value={appAllowedOrigins} onChange={(e) => setAppAllowedOrigins(e.target.value)} />
              </div>
              <div className="form-group">
                <label className="form-label">CLIENT TYPE</label>
                <select className="form-input" value={appAuthMethod} onChange={(e) => setAppAuthMethod(e.target.value)}>
                  <option value="none">Public SPA / Mobile (PKCE S256, no secret)</option>
                  <option value="client_secret_post">Confidential Backend (PKCE + client_secret)</option>
                </select>
              </div>
              <button type="submit" className="btn-primary-deck" disabled={creatingApp}>
                {creatingApp ? 'REGISTERING...' : 'REGISTER APPLICATION'}
              </button>
            </form>

            {revealedSecret && (
              <div style={{ marginTop: '12px', padding: '12px', background: 'rgba(234, 179, 8, 0.15)', border: '1px solid #eab308', borderRadius: '6px', fontSize: '12px' }}>
                <strong>Save your client secret now (shown once):</strong><br />
                <code>client_id={revealedSecret.clientId}</code><br />
                <code>client_secret={revealedSecret.clientSecret}</code>
              </div>
            )}

            <h4 className="section-title" style={{ marginTop: '20px' }}>REGISTERED APPLICATIONS ({clients.length})</h4>
            {clients.length === 0 ? (
              <p className="empty-state">No applications registered in this tenant yet.</p>
            ) : (
              <div className="sessions-list">
                {clients.map((c) => (
                  <div key={c.clientId} className="session-card" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: '6px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', width: '100%', alignItems: 'center' }}>
                      <strong>{c.name} (<code>{c.clientId}</code>)</strong>
                      <div style={{ display: 'flex', gap: '8px' }}>
                        {c.tokenEndpointAuthMethod === 'client_secret_post' && (
                          <button type="button" className="btn-secondary-deck" onClick={() => handleRotateSecret(c.clientId)}>Rotate Secret</button>
                        )}
                        <button type="button" className="btn-secondary-deck" onClick={() => handleToggleClient(c)}>
                          {c.enabled ? 'Disable' : 'Enable'}
                        </button>
                      </div>
                    </div>
                    <div style={{ fontSize: '12px', opacity: 0.85 }}>
                      Redirects: <code>{(c.redirectUris || []).join(', ')}</code><br />
                      Origins: <code>{(c.allowedOrigins || []).join(', ') || 'none'}</code> | Scopes: <code>{(c.allowedScopes || ['openid', 'profile', 'email']).join(' ')}</code>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="profile-form-card" style={{ marginTop: '16px' }}>
            <h4 className="section-title">SUBSCRIPTION &amp; ENTITLEMENTS (STRIPE TEST MODE)</h4>
            <p style={{ fontSize: '12px', opacity: 0.85 }}>
              Current Plan: <strong>{billing?.plan?.toUpperCase() || 'DEVELOPER'}</strong> | Status: <strong>{billing?.billing?.subscriptionStatus || 'free'}</strong>
              {!billing?.stripeConfigured && ' (Stripe test keys not attached yet — checkout unlocks once STRIPE_SECRET_KEY=sk_test_... is configured)'}
            </p>
            <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', marginTop: '8px' }}>
              <button type="button" className="btn-secondary-deck" onClick={() => handleUpgrade('launch')}>Launch ($29/mo)</button>
              <button type="button" className="btn-secondary-deck" onClick={() => handleUpgrade('growth')}>Growth ($99/mo)</button>
              <button type="button" className="btn-secondary-deck" onClick={() => handleUpgrade('scale')}>Scale ($299/mo)</button>
            </div>
          </div>

          <div className="profile-form-card" style={{ marginTop: '16px' }}>
            <h4 className="section-title">THREADLINE REFERENCE QUICK-START</h4>
            <pre style={{ fontSize: '11px', overflowX: 'auto', background: 'rgba(15, 23, 42, 0.8)', padding: '12px', borderRadius: '6px' }}>
{`// 1. Frontend PKCE S256 redirect to ${discovery?.authorization_endpoint || `${authBackendUrl}/oauth/authorize`}
// 2. Exchange code at POST ${discovery?.token_endpoint || `${authBackendUrl}/oauth/token`}
// 3. Backend API JWT verification (RS256 via JWKS ${discovery?.jwks_uri || `${authBackendUrl}/.well-known/jwks.json`}):
//    Verify alg=RS256, iss="${discovery?.issuer || ''}", aud="<your_client_id>", exp, nbf`}
            </pre>
          </div>

          <div className="profile-form-card" style={{ marginTop: '16px' }}>
            <h4 className="section-title">TENANT AUDIT ACTIVITY ({auditLogs.length})</h4>
            {auditLogs.length === 0 ? (
              <p className="empty-state">No tenant audit events recorded yet.</p>
            ) : (
              <div className="sessions-list">
                {auditLogs.map((log, i) => (
                  <div key={log.auditId || i} className="session-card" style={{ fontSize: '12px' }}>
                    <span><strong>{log.operation}</strong> ({log.outcome}) — {log.clientId || 'tenant'}</span>
                    <span>{log.timestamp || ''}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  )
}
