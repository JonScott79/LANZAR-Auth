import { useState, useEffect } from 'react';
import { fetchClients } from './adminApi.js';

export default function DeckApplications() {
  const [clients, setClients] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    async function load() {
      try {
        setLoading(true);
        const data = await fetchClients();
        setClients(data.clients || []);
      } catch (err) {
        console.error('Failed to load clients:', err);
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      <div className="mc-deck-header">
        <div className="mc-deck-title-wrap">
          <span className="mc-deck-tag">DECK 04 // APPLICATION REGISTRY</span>
          <h1 className="mc-deck-title">APPLICATION REGISTRY</h1>
          <p className="mc-deck-subtitle">
            Authoritative inventory of OAuth 2.0 / PKCE client applications, redirect whitelist boundaries, and CORS permissions.
          </p>
        </div>
      </div>

      {error && (
        <div style={{ padding: "1rem", background: "var(--mc-rose-dim)", border: "1px solid var(--mc-rose)", borderRadius: "6px", color: "var(--mc-rose)", fontFamily: "var(--mc-font-mono)", fontSize: "0.82rem" }}>
          CLIENT REGISTRY LOOKUP ERROR: {error}
        </div>
      )}

      {/* Grid of registered clients */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(340px, 1fr))", gap: "1.25rem" }}>
        {loading ? (
          <div style={{ color: "var(--mc-text-dim)", padding: "2rem" }}>Loading application registry...</div>
        ) : (
          clients.map(app => (
            <div key={app.id} className="mc-panel" style={{ borderColor: "var(--mc-border)" }}>
              <div className="mc-panel-header">
                <div>
                  <div style={{ fontSize: "0.68rem", fontFamily: "var(--mc-font-mono)", color: "var(--mc-cyan)" }}>
                    CLIENT ID: {app.id}
                  </div>
                  <h4 style={{ margin: "2px 0 0 0", fontSize: "1.05rem", color: "#fff" }}>{app.name}</h4>
                </div>
                <span className={`mc-badge ${app.enabled ? 'nominal' : 'alert'}`}>
                  {app.enabled ? 'ACTIVE' : 'DISABLED'}
                </span>
              </div>

              <div className="mc-panel-body" style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.78rem" }}>
                  <span style={{ color: "var(--mc-text-dim)", fontFamily: "var(--mc-font-mono)" }}>AUTHORIZATION:</span>
                  <span style={{ color: "var(--mc-gold)", fontFamily: "var(--mc-font-mono)", fontWeight: "700" }}>OAuth 2.0 + PKCE (S256)</span>
                </div>

                <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.78rem" }}>
                  <span style={{ color: "var(--mc-text-dim)", fontFamily: "var(--mc-font-mono)" }}>TENANT BOUNDARY:</span>
                  <span style={{ color: "#fff", fontFamily: "var(--mc-font-mono)" }}>tenant_id: "lanzar"</span>
                </div>

                <div>
                  <div style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.7rem", color: "var(--mc-text-dim)", marginBottom: "0.35rem" }}>
                    STRICT REDIRECT URI WHITELIST ({app.redirectUris?.length || 0}):
                  </div>
                  <div style={{ background: "var(--mc-bg-deep)", border: "1px solid var(--mc-border)", borderRadius: "4px", padding: "0.5rem", maxHeight: "120px", overflowY: "auto" }}>
                    {app.redirectUris && app.redirectUris.map((uri, idx) => (
                      <div key={idx} style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.68rem", color: "var(--mc-text-muted)", wordBreak: "break-all", marginBottom: "2px" }}>
                        • {uri}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
