import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { fetchTelemetry, fetchAuditLogs } from './adminApi.js';

export default function DeckOverview() {
  const [telemetry, setTelemetry] = useState(null);
  const [recentLogs, setRecentLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    async function loadData() {
      try {
        setLoading(true);
        const [telData, logData] = await Promise.all([
          fetchTelemetry(),
          fetchAuditLogs(10)
        ]);
        setTelemetry(telData);
        setRecentLogs(logData.logs || []);
      } catch (err) {
        console.error('Failed to load overview telemetry:', err);
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }
    loadData();
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, []);

  const totalUsers = telemetry?.totalUsers || 0;
  const mfaCount = telemetry?.mfaEnrolledCount || 0;
  const mfaPercent = totalUsers > 0 ? Math.round((mfaCount / totalUsers) * 100) : 0;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      {/* Header Banner */}
      <div className="mc-deck-header">
        <div className="mc-deck-title-wrap">
          <span className="mc-deck-tag">DECK 01 // SECTOR RADAR</span>
          <h1 className="mc-deck-title">OPERATIONS OVERVIEW</h1>
          <p className="mc-deck-subtitle">
            Real-time ecosystem identity telemetry, token velocity, and security health across all LANZAR sectors.
          </p>
        </div>
        <div className="mc-deck-actions">
          <button className="mc-btn mc-btn-secondary" onClick={() => window.location.reload()}>
            <span>&#8635;</span> REFRESH RADAR
          </button>
          <button className="mc-btn mc-btn-primary" onClick={() => navigate('/admin/identities')}>
            <span>+</span> EXPLORE IDENTITIES
          </button>
        </div>
      </div>

      {error && (
        <div style={{ padding: "1rem", background: "var(--mc-rose-dim)", border: "1px solid var(--mc-rose)", borderRadius: "6px", color: "var(--mc-rose)", fontFamily: "var(--mc-font-mono)", fontSize: "0.82rem" }}>
          SYSTEM TELEMETRY ALERT: {error}
        </div>
      )}

      {/* Primary Telemetry Metrics */}
      <div className="mc-grid-metrics">
        <div className="mc-metric-card gold">
          <span className="mc-metric-label">TOTAL IDENTITIES</span>
          <div className="mc-metric-value">{loading ? '...' : totalUsers}</div>
          <div className="mc-metric-sub">
            <span className="mc-badge gold">CANONICAL PROFILES</span>
          </div>
        </div>

        <div className="mc-metric-card emerald">
          <span className="mc-metric-label">ACTIVE RATIO</span>
          <div className="mc-metric-value">{loading ? '...' : (telemetry?.activeUsers || 0)}</div>
          <div className="mc-metric-sub">
            <span className="mc-badge nominal">&#10003; NOMINAL STATUS</span>
          </div>
        </div>

        <div className="mc-metric-card cyan">
          <span className="mc-metric-label">MFA ENFORCEMENT</span>
          <div className="mc-metric-value">{loading ? '...' : `${mfaPercent}%`}</div>
          <div className="mc-metric-sub">
            <span className="mc-badge cyan">{mfaCount} ENROLLED</span>
          </div>
        </div>

        <div className="mc-metric-card amber">
          <span className="mc-metric-label">FOUNDER ROSTER</span>
          <div className="mc-metric-value">{loading ? '...' : (telemetry?.founderCount || 0)}</div>
          <div className="mc-metric-sub">
            <span className="mc-badge warning">AUTHORITATIVE</span>
          </div>
        </div>
      </div>

      {/* Two Column Layout: Quick Actions & Live Stream */}
      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: "1.5rem" }}>
        {/* Live Security Stream Panel */}
        <div className="mc-panel">
          <div className="mc-panel-header">
            <h3 className="mc-panel-title">
              <span style={{ color: "var(--mc-cyan)" }}>&#9672;</span> LIVE SECURITY EVENT STREAM
            </h3>
            <button className="mc-btn mc-btn-secondary" style={{ padding: "3px 8px", fontSize: "0.7rem" }} onClick={() => navigate('/admin/audit')}>
              VIEW ALL &rarr;
            </button>
          </div>
          <div className="mc-panel-body" style={{ padding: "0" }}>
            <div className="mc-table-container" style={{ border: "none", borderRadius: "0" }}>
              <table className="mc-table">
                <thead>
                  <tr>
                    <th>TIMESTAMP</th>
                    <th>EVENT ACTION</th>
                    <th>TARGET</th>
                    <th>STATUS</th>
                  </tr>
                </thead>
                <tbody>
                  {recentLogs.length === 0 ? (
                    <tr>
                      <td colSpan="4" style={{ textAlign: "center", padding: "2rem", color: "var(--mc-text-dim)" }}>
                        No recent security events recorded in radar buffer.
                      </td>
                    </tr>
                  ) : (
                    recentLogs.map((log, idx) => (
                      <tr key={idx}>
                        <td style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.72rem", color: "var(--mc-text-muted)" }}>
                          {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : 'NOW'}
                        </td>
                        <td style={{ fontFamily: "var(--mc-font-mono)", fontWeight: "700" }}>
                          {log.action}
                        </td>
                        <td style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.75rem", color: "var(--mc-cyan)" }}>
                          {log.targetUid || log.email || 'SYSTEM'}
                        </td>
                        <td>
                          <span className={`mc-badge ${log.status === 'success' ? 'nominal' : 'alert'}`}>
                            {(log.status || 'LOGGED').toUpperCase()}
                          </span>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Rapid Sector Actions Card */}
        <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          <div className="mc-panel">
            <div className="mc-panel-header">
              <h3 className="mc-panel-title">
                <span style={{ color: "var(--mc-gold)" }}>&#9881;</span> RAPID SECTOR LAUNCHERS
              </h3>
            </div>
            <div className="mc-panel-body" style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
              <button className="mc-btn mc-btn-secondary" style={{ justifyContent: "flex-start", padding: "10px" }} onClick={() => navigate('/admin/identities')}>
                <span style={{ fontSize: "1.1rem" }}>🔑</span>
                <div style={{ textAlign: "left" }}>
                  <div style={{ fontWeight: "700" }}>Inspect User Account</div>
                  <div style={{ fontSize: "0.7rem", color: "var(--mc-text-dim)" }}>Look up profile, sessions, or badges</div>
                </div>
              </button>

              <button className="mc-btn mc-btn-secondary" style={{ justifyContent: "flex-start", padding: "10px" }} onClick={() => navigate('/admin/founders')}>
                <span style={{ fontSize: "1.1rem" }}>🎖</span>
                <div style={{ textAlign: "left" }}>
                  <div style={{ fontWeight: "700" }}>Award Founder Designation</div>
                  <div style={{ fontSize: "0.7rem", color: "var(--mc-text-dim)" }}>Grant authoritative badge & number</div>
                </div>
              </button>

              <button className="mc-btn mc-btn-secondary" style={{ justifyContent: "flex-start", padding: "10px" }} onClick={() => navigate('/admin/security')}>
                <span style={{ fontSize: "1.1rem" }}>🛡</span>
                <div style={{ textAlign: "left" }}>
                  <div style={{ fontWeight: "700" }}>Security Center & MFA</div>
                  <div style={{ fontSize: "0.7rem", color: "var(--mc-text-dim)" }}>Review lockouts & recovery requests</div>
                </div>
              </button>

              <button className="mc-btn mc-btn-secondary" style={{ justifyContent: "flex-start", padding: "10px" }} onClick={() => navigate('/admin/terminal')}>
                <span style={{ fontSize: "1.1rem" }}>💳</span>
                <div style={{ textAlign: "left" }}>
                  <div style={{ fontWeight: "700" }}>Virtual Card Terminal</div>
                  <div style={{ fontSize: "0.7rem", color: "var(--mc-text-dim)" }}>Process client credit card transaction</div>
                </div>
              </button>
            </div>
          </div>

          {/* System Environment Callout */}
          <div className="mc-panel" style={{ background: "var(--mc-bg-deep)", borderColor: "rgba(255, 215, 0, 0.2)" }}>
            <div className="mc-panel-body" style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.65rem", color: "var(--mc-text-dim)" }}>ENGINE STATUS</span>
                <span className="mc-badge nominal">&#9679; ONLINE</span>
              </div>
              <div style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.75rem", color: "var(--mc-text-main)" }}>
                RAILWAY CLOUD CONTAINER: NOMINAL
              </div>
              <div style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.68rem", color: "var(--mc-cyan)" }}>
                auth-api.lanzar.me // PORT 4001
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
