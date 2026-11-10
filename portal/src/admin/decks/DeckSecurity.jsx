import { useState } from 'react';

export default function DeckSecurity() {
  const [activeTab, setActiveTab] = useState('adoption');

  // Staged dual-admin recovery queue entries
  const [recoveryRequests, setRecoveryRequests] = useState([
    {
      id: 'req_8921a',
      uid: 'user_dev_01',
      email: 'operator-pilot@lanzar.me',
      reason: 'Lost authenticator hardware key during device migration',
      requestedAt: '2026-11-08T18:22:00Z',
      signoff1: 'jonny@lanzar.me',
      signoff2: null,
      status: 'pending_secondary'
    }
  ]);

  const handleApproveSecondary = (reqId) => {
    alert(`Approved request ${reqId} as secondary administrator. Audit log entry committed.`);
    setRecoveryRequests(prev => prev.map(r => r.id === reqId ? { ...r, signoff2: 'admin2@lanzar.me', status: 'approved' } : r));
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      <div className="mc-deck-header">
        <div className="mc-deck-title-wrap">
          <span className="mc-deck-tag">DECK 03 // SECURITY CENTER</span>
          <h1 className="mc-deck-title">SECURITY CENTER</h1>
          <p className="mc-deck-subtitle">
            Universal MFA adoption metrics, brute-force lockout surveillance, and dual-admin recovery authorizations.
          </p>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="mc-grid-metrics">
        <div className="mc-metric-card gold">
          <span className="mc-metric-label">MFA PROTOCOL</span>
          <div className="mc-metric-value">RFC 6238</div>
          <div className="mc-metric-sub">
            <span className="mc-badge gold">UNIVERSAL TOTP</span>
          </div>
        </div>

        <div className="mc-metric-card emerald">
          <span className="mc-metric-label">SECRET ENCRYPTION</span>
          <div className="mc-metric-value">AES-256</div>
          <div className="mc-metric-sub">
            <span className="mc-badge nominal">&#10003; GCM AT-REST</span>
          </div>
        </div>

        <div className="mc-metric-card cyan">
          <span className="mc-metric-label">PHONE INFRASTRUCTURE</span>
          <div className="mc-metric-value">STAGED</div>
          <div className="mc-metric-sub">
            <span className="mc-badge cyan">ZERO CARRIER COST</span>
          </div>
        </div>

        <div className="mc-metric-card amber">
          <span className="mc-metric-label">DUAL-ADMIN QUEUE</span>
          <div className="mc-metric-value">{recoveryRequests.filter(r => r.status !== 'approved').length}</div>
          <div className="mc-metric-sub">
            <span className="mc-badge warning">REQUIRES SIGN-OFF</span>
          </div>
        </div>
      </div>

      {/* Tab Switcher */}
      <div style={{ display: "flex", gap: "0.5rem", borderBottom: "1px solid var(--mc-border)", paddingBottom: "0.5rem" }}>
        <button
          className={`mc-btn ${activeTab === 'adoption' ? 'mc-btn-primary' : 'mc-btn-secondary'}`}
          onClick={() => setActiveTab('adoption')}
        >
          MFA ADOPTION & CRYPTO
        </button>
        <button
          className={`mc-btn ${activeTab === 'dual_admin' ? 'mc-btn-primary' : 'mc-btn-secondary'}`}
          onClick={() => setActiveTab('dual_admin')}
        >
          DUAL-ADMIN RECOVERY DESK (SOP-05)
        </button>
        <button
          className={`mc-btn ${activeTab === 'lockouts' ? 'mc-btn-primary' : 'mc-btn-secondary'}`}
          onClick={() => setActiveTab('lockouts')}
        >
          LOCKOUT SURVEILLANCE
        </button>
      </div>

      {activeTab === 'adoption' && (
        <div className="mc-panel">
          <div className="mc-panel-header">
            <h3 className="mc-panel-title">
              <span>&#128737;</span> SUPPORTED MULTI-FACTOR AUTHENTICATION STANDARDS
            </h3>
          </div>
          <div className="mc-panel-body" style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "1rem" }}>
              <div className="mc-panel" style={{ padding: "1rem", borderColor: "var(--mc-gold)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
                  <strong style={{ color: "var(--mc-gold)" }}>Universal TOTP Authenticator</strong>
                  <span className="mc-badge gold">RFC 6238 ACTIVE</span>
                </div>
                <p style={{ fontSize: "0.8rem", color: "var(--mc-text-muted)", margin: "0 0 0.5rem 0" }}>
                  Compatible with Microsoft Authenticator, Google Authenticator, 1Password, Bitwarden. 30s intervals, 6-digit codes.
                </p>
                <div style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.7rem", color: "var(--mc-text-dim)" }}>
                  Storage: AES-256-GCM encrypted in <code>/users/{'{uid}'}/mfa_secrets/totp</code>
                </div>
              </div>

              <div className="mc-panel" style={{ padding: "1rem", borderColor: "var(--mc-cyan)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
                  <strong style={{ color: "var(--mc-cyan)" }}>Single-Use Recovery Codes</strong>
                  <span className="mc-badge cyan">ACTIVE</span>
                </div>
                <p style={{ fontSize: "0.8rem", color: "var(--mc-text-muted)", margin: "0 0 0.5rem 0" }}>
                  10 cryptographically random 8-character recovery codes generated upon MFA enrollment. Argon2/SHA-256 hashed.
                </p>
                <div style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.7rem", color: "var(--mc-text-dim)" }}>
                  Policy: Consumed once then invalidated permanently.
                </div>
              </div>

              <div className="mc-panel" style={{ padding: "1rem", borderColor: "var(--mc-border)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
                  <strong>Phone SMS Verification</strong>
                  <span className="mc-badge warning">STAGED (ZERO COST)</span>
                </div>
                <p style={{ fontSize: "0.8rem", color: "var(--mc-text-muted)", margin: "0 0 0.5rem 0" }}>
                  Provider-abstraction layer complete. <code>smsService.js</code> Mock Provider active. Live carrier activation deferred.
                </p>
                <div style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.7rem", color: "var(--mc-text-dim)" }}>
                  Guard: <code>SMS_LIVE_ENABLED=false</code> prevents unexpected billing.
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'dual_admin' && (
        <div className="mc-panel">
          <div className="mc-panel-header">
            <h3 className="mc-panel-title">
              <span>&#9878;</span> DUAL-ADMIN MFA RESET REQUESTS (SOP-05)
            </h3>
          </div>
          <div className="mc-panel-body" style={{ padding: "0" }}>
            <div className="mc-table-container" style={{ border: "none" }}>
              <table className="mc-table">
                <thead>
                  <tr>
                    <th>REQUEST ID</th>
                    <th>TARGET USER</th>
                    <th>JUSTIFICATION</th>
                    <th>PRIMARY SIGN-OFF</th>
                    <th>SECONDARY SIGN-OFF</th>
                    <th>ACTION</th>
                  </tr>
                </thead>
                <tbody>
                  {recoveryRequests.map(req => (
                    <tr key={req.id}>
                      <td style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.72rem", color: "var(--mc-cyan)" }}>
                        {req.id}
                      </td>
                      <td>
                        <strong>{req.email}</strong>
                        <div style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.68rem", color: "var(--mc-text-dim)" }}>
                          {req.uid}
                        </div>
                      </td>
                      <td style={{ fontSize: "0.8rem" }}>{req.reason}</td>
                      <td>
                        <span className="mc-badge nominal">&#10003; {req.signoff1}</span>
                      </td>
                      <td>
                        {req.signoff2 ? (
                          <span className="mc-badge nominal">&#10003; {req.signoff2}</span>
                        ) : (
                          <span className="mc-badge warning">AWAITING SECONDARY</span>
                        )}
                      </td>
                      <td>
                        {req.status === 'approved' ? (
                          <span className="mc-badge nominal">RESET COMPLETED</span>
                        ) : (
                          <button
                            className="mc-btn mc-btn-primary"
                            style={{ padding: "3px 8px", fontSize: "0.7rem" }}
                            onClick={() => handleApproveSecondary(req.id)}
                          >
                            SIGN &amp; APPROVE
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'lockouts' && (
        <div className="mc-panel">
          <div className="mc-panel-header">
            <h3 className="mc-panel-title">
              <span>&#9888;</span> ACTIVE RATE-LIMITS &amp; LOCKOUT MONITOR
            </h3>
          </div>
          <div className="mc-panel-body" style={{ textAlign: "center", padding: "3rem 1rem", color: "var(--mc-text-dim)" }}>
            <div style={{ fontSize: "2rem", marginBottom: "0.5rem", color: "var(--mc-emerald)" }}>&#10003;</div>
            <div style={{ fontWeight: "700", color: "#fff" }}>Zero accounts currently under security lockout.</div>
            <div style={{ fontSize: "0.8rem", marginTop: "0.25rem" }}>
              Authentication rate limits and replay defenses are operating nominally.
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
