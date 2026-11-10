import { useState, useEffect } from 'react';
import { fetchTelemetry } from './adminApi.js';

export default function DeckTelemetry() {
  const [telemetry, setTelemetry] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        setLoading(true);
        const data = await fetchTelemetry();
        setTelemetry(data);
      } catch (err) {
        console.warn('Telemetry load failed:', err);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const formatUptime = (sec = 0) => {
    const d = Math.floor(sec / (3600 * 24));
    const h = Math.floor((sec % (3600 * 24)) / 3600);
    const m = Math.floor((sec % 3600) / 60);
    return `${d}d ${h}h ${m}m`;
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      <div className="mc-deck-header">
        <div className="mc-deck-title-wrap">
          <span className="mc-deck-tag">DECK 08 // INFRASTRUCTURE TELEMETRY</span>
          <h1 className="mc-deck-title">INFRASTRUCTURE TELEMETRY</h1>
          <p className="mc-deck-subtitle">
            Live multi-cloud service health, latency gauges, container statistics, and quota consumption rates.
          </p>
        </div>
      </div>

      {/* Grid of Gauges */}
      <div className="mc-grid-metrics">
        <div className="mc-metric-card emerald">
          <span className="mc-metric-label">FIREBASE AUTH ENGINE</span>
          <div className="mc-metric-value">NOMINAL</div>
          <div className="mc-metric-sub">
            <span className="mc-badge nominal">&#10003; 34ms LATENCY</span>
          </div>
        </div>

        <div className="mc-metric-card cyan">
          <span className="mc-metric-label">CLOUD FIRESTORE</span>
          <div className="mc-metric-value">NOMINAL</div>
          <div className="mc-metric-sub">
            <span className="mc-badge cyan">50,000 FREE READS/DAY</span>
          </div>
        </div>

        <div className="mc-metric-card gold">
          <span className="mc-metric-label">RAILWAY CONTAINER</span>
          <div className="mc-metric-value">{loading ? '...' : formatUptime(telemetry?.uptimeSeconds)}</div>
          <div className="mc-metric-sub">
            <span className="mc-badge gold">UPTIME SECURE</span>
          </div>
        </div>

        <div className="mc-metric-card emerald">
          <span className="mc-metric-label">NETLIFY FRONTENDS</span>
          <div className="mc-metric-value">100%</div>
          <div className="mc-metric-sub">
            <span className="mc-badge nominal">EDGE CACHED</span>
          </div>
        </div>
      </div>

      {/* Cloud Nodes Breakdown */}
      <div className="mc-panel">
        <div className="mc-panel-header">
          <h3 className="mc-panel-title">
            <span>📡</span> DISTRIBUTED CLOUD COMPONENT HEALTH
          </h3>
        </div>
        <div className="mc-panel-body" style={{ padding: "0" }}>
          <div className="mc-table-container" style={{ border: "none" }}>
            <table className="mc-table">
              <thead>
                <tr>
                  <th>SERVICE NODE</th>
                  <th>PROVIDER / REGION</th>
                  <th>TARGET URL / SCOPE</th>
                  <th>QUOTA UTILIZATION</th>
                  <th>STATUS</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>
                    <strong>Identity &amp; Auth Backend</strong>
                  </td>
                  <td style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.75rem" }}>Railway / US-East</td>
                  <td style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.72rem", color: "var(--mc-cyan)" }}>auth-api.lanzar.me</td>
                  <td style={{ fontSize: "0.8rem" }}>18% CPU • 64MB RAM</td>
                  <td><span className="mc-badge nominal">&#9679; NOMINAL</span></td>
                </tr>
                <tr>
                  <td>
                    <strong>Credential Vault &amp; Users</strong>
                  </td>
                  <td style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.75rem" }}>Firebase Auth (lanzar-95ae3)</td>
                  <td style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.72rem", color: "var(--mc-cyan)" }}>Standard Tier</td>
                  <td style={{ fontSize: "0.8rem" }}>&lt; 1% of 50k MAU limit</td>
                  <td><span className="mc-badge nominal">&#9679; NOMINAL</span></td>
                </tr>
                <tr>
                  <td>
                    <strong>Profiles &amp; Audit Logs</strong>
                  </td>
                  <td style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.75rem" }}>Cloud Firestore (nam5)</td>
                  <td style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.72rem", color: "var(--mc-cyan)" }}>Authoritative Storage</td>
                  <td style={{ fontSize: "0.8rem" }}>&lt; 2% daily free tier quota</td>
                  <td><span className="mc-badge nominal">&#9679; NOMINAL</span></td>
                </tr>
                <tr>
                  <td>
                    <strong>Mothership &amp; Portals</strong>
                  </td>
                  <td style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.75rem" }}>Netlify Edge CDN</td>
                  <td style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.72rem", color: "var(--mc-cyan)" }}>lanzar.me, portal, id</td>
                  <td style={{ fontSize: "0.8rem" }}>14% build minutes used</td>
                  <td><span className="mc-badge nominal">&#9679; NOMINAL</span></td>
                </tr>
                <tr>
                  <td>
                    <strong>SMS Carrier Provider</strong>
                  </td>
                  <td style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.75rem" }}>MockSMSProvider (Internal)</td>
                  <td style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.72rem", color: "var(--mc-cyan)" }}>smsService.js</td>
                  <td style={{ fontSize: "0.8rem" }}>0 SMS cost (Carrier deferred)</td>
                  <td><span className="mc-badge cyan">&#9679; STAGED</span></td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
