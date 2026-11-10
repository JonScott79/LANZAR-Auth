import { useState, useEffect } from 'react';
import { fetchAuditLogs } from './adminApi.js';

export default function DeckAudit() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filterAction, setFilterAction] = useState('all');
  const [selectedLog, setSelectedLog] = useState(null);

  const loadLogs = async () => {
    try {
      setLoading(true);
      const data = await fetchAuditLogs(100);
      setLogs(data.logs || []);
    } catch (err) {
      console.error('Failed to load audit logs:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadLogs();
  }, []);

  const filtered = logs.filter(l => {
    if (filterAction === 'all') return true;
    return (l.action || '').toLowerCase().includes(filterAction.toLowerCase());
  });

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      <div className="mc-deck-header">
        <div className="mc-deck-title-wrap">
          <span className="mc-deck-tag">DECK 09 // AUDIT CENTER</span>
          <h1 className="mc-deck-title">SECURITY AUDIT CENTER</h1>
          <p className="mc-deck-subtitle">
            Tamper-resistant append-only security logs, administrative attribution, and forensic event stream.
          </p>
        </div>
        <div className="mc-deck-actions">
          <button className="mc-btn mc-btn-secondary" onClick={loadLogs}>
            &#8635; REFRESH STREAM
          </button>
        </div>
      </div>

      {/* Filter and Table */}
      <div className="mc-panel">
        <div className="mc-panel-header">
          <div style={{ display: "flex", gap: "1rem", alignItems: "center" }}>
            <h3 className="mc-panel-title">
              <span>📜</span> EVENT LOGS ({filtered.length})
            </h3>
            <select
              className="mc-select"
              value={filterAction}
              onChange={e => setFilterAction(e.target.value)}
            >
              <option value="all">ALL SECURITY ACTIONS</option>
              <option value="LOGIN">LOGIN &amp; AUTH</option>
              <option value="FOUNDER">FOUNDER MUTATIONS</option>
              <option value="MFA">MFA CHALLENGES</option>
              <option value="STATUS">STATUS CHANGES</option>
              <option value="SESSION">SESSION REVOCATIONS</option>
            </select>
          </div>
        </div>

        <div className="mc-panel-body" style={{ padding: "0" }}>
          <div className="mc-table-container" style={{ border: "none" }}>
            <table className="mc-table">
              <thead>
                <tr>
                  <th>TIMESTAMP (UTC)</th>
                  <th>ACTION</th>
                  <th>ACTOR / ADMIN</th>
                  <th>TARGET RESOURCE</th>
                  <th>IP ORIGIN</th>
                  <th>STATUS</th>
                  <th style={{ textAlign: "right" }}>PAYLOAD</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan="7" style={{ textAlign: "center", padding: "2rem", color: "var(--mc-text-dim)" }}>
                      Streaming logs from tamper-resistant security ledger...
                    </td>
                  </tr>
                ) : filtered.length === 0 ? (
                  <tr>
                    <td colSpan="7" style={{ textAlign: "center", padding: "2rem", color: "var(--mc-text-dim)" }}>
                      No matching security events found.
                    </td>
                  </tr>
                ) : (
                  filtered.map((log, idx) => (
                    <tr key={idx}>
                      <td style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.72rem", color: "var(--mc-text-muted)" }}>
                        {log.timestamp ? new Date(log.timestamp).toISOString().replace('T', ' ').substring(0, 19) : '—'}
                      </td>
                      <td style={{ fontFamily: "var(--mc-font-mono)", fontWeight: "700" }}>
                        {log.action}
                      </td>
                      <td style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.75rem" }}>
                        {log.actorUid || 'SYSTEM'}
                      </td>
                      <td style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.72rem", color: "var(--mc-cyan)" }}>
                        {log.targetUid || log.email || '—'}
                      </td>
                      <td style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.72rem", color: "var(--mc-text-dim)" }}>
                        {log.ipAddress || '127.0.0.1'}
                      </td>
                      <td>
                        <span className={`mc-badge ${log.status === 'success' ? 'nominal' : 'alert'}`}>
                          {(log.status || 'OK').toUpperCase()}
                        </span>
                      </td>
                      <td style={{ textAlign: "right" }}>
                        <button
                          className="mc-btn mc-btn-secondary"
                          style={{ padding: "3px 8px", fontSize: "0.68rem" }}
                          onClick={() => setSelectedLog(log)}
                        >
                          JSON &rarr;
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* JSON Payload Inspector Modal */}
      {selectedLog && (
        <div className="mc-modal-backdrop" onClick={() => setSelectedLog(null)}>
          <div className="mc-modal" style={{ maxWidth: "650px" }} onClick={e => e.stopPropagation()}>
            <div className="mc-modal-header" style={{ background: "var(--mc-bg-elevated)", borderColor: "var(--mc-border)" }}>
              <span style={{ fontSize: "1.1rem", color: "var(--mc-cyan)" }}>&#9672;</span>
              <h3 className="mc-modal-title" style={{ color: "#fff" }}>SECURITY AUDIT LOG PAYLOAD</h3>
            </div>
            <div className="mc-modal-body" style={{ padding: "1rem" }}>
              <pre style={{ background: "var(--mc-bg-deep)", border: "1px solid var(--mc-border)", borderRadius: "6px", padding: "1rem", color: "var(--mc-gold)", fontFamily: "var(--mc-font-mono)", fontSize: "0.75rem", overflowX: "auto", maxHeight: "400px", margin: "0" }}>
                {JSON.stringify(selectedLog, null, 2)}
              </pre>
            </div>
            <div className="mc-modal-footer">
              <button className="mc-btn mc-btn-secondary" onClick={() => setSelectedLog(null)}>
                CLOSE
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
