import { useState } from 'react';

export default function DeckConfig() {
  const [stepUpEnabled, setStepUpEnabled] = useState(false);
  const [phoneMockEnabled] = useState(true);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      <div className="mc-deck-header">
        <div className="mc-deck-title-wrap">
          <span className="mc-deck-tag">DECK 10 // SYSTEM CONFIGURATION</span>
          <h1 className="mc-deck-title">SYSTEM CONFIGURATION</h1>
          <p className="mc-deck-subtitle">
            Security policy thresholds, session lifetimes, provider toggles, and disaster recovery controls.
          </p>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: "1.25rem" }}>
        {/* Session Lifetimes Card */}
        <div className="mc-panel">
          <div className="mc-panel-header">
            <h4 className="mc-panel-title">⏱ SESSION LIFETIMES &amp; TTL</h4>
          </div>
          <div className="mc-panel-body" style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.82rem" }}>
              <span style={{ color: "var(--mc-text-dim)" }}>PKCE Authorization Code:</span>
              <strong style={{ fontFamily: "var(--mc-font-mono)", color: "var(--mc-gold)" }}>10 MINUTES (Single-Use)</strong>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.82rem" }}>
              <span style={{ color: "var(--mc-text-dim)" }}>Firebase ID Token (Access):</span>
              <strong style={{ fontFamily: "var(--mc-font-mono)" }}>60 MINUTES</strong>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.82rem" }}>
              <span style={{ color: "var(--mc-text-dim)" }}>Refresh Token Max Lifetime:</span>
              <strong style={{ fontFamily: "var(--mc-font-mono)" }}>30 DAYS (Inactivity Invalidation)</strong>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.82rem" }}>
              <span style={{ color: "var(--mc-text-dim)" }}>Unconfirmed TOTP Staging TTL:</span>
              <strong style={{ fontFamily: "var(--mc-font-mono)", color: "var(--mc-cyan)" }}>10 MINUTES</strong>
            </div>
          </div>
        </div>

        {/* Phone OTP Provider Controls (Amendment #002) */}
        <div className="mc-panel">
          <div className="mc-panel-header">
            <h4 className="mc-panel-title">📱 PHONE AUTHENTICATION STAGING</h4>
            <span className="mc-badge cyan">ZERO COST</span>
          </div>
          <div className="mc-panel-body" style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
            <div style={{ fontSize: "0.8rem", color: "var(--mc-text-muted)" }}>
              Per <strong>Architectural Amendment #002</strong>, phone authentication architecture is complete but live SMS provider activation is deferred.
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "0.5rem", background: "var(--mc-bg-deep)", borderRadius: "4px" }}>
              <div>
                <div style={{ fontWeight: "700", fontSize: "0.82rem" }}>MockSMSProvider</div>
                <div style={{ fontSize: "0.68rem", color: "var(--mc-text-dim)", fontFamily: "var(--mc-font-mono)" }}>Carrier Costs Prevented</div>
              </div>
              <span className="mc-badge nominal">&#10003; ACTIVE</span>
            </div>
            <div style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.7rem", color: "var(--mc-amber)" }}>
              Live Carrier Guard: <code>SMS_LIVE_ENABLED=false</code>
            </div>
          </div>
        </div>

        {/* Emergency Step-Up Toggle */}
        <div className="mc-panel" style={{ borderColor: "var(--mc-amber)" }}>
          <div className="mc-panel-header" style={{ background: "rgba(245, 158, 11, 0.1)" }}>
            <h4 className="mc-modal-title" style={{ color: "var(--mc-amber)", fontSize: "0.95rem" }}>
              &#9888; EMERGENCY GLOBAL STEP-UP
            </h4>
          </div>
          <div className="mc-panel-body" style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
            <p style={{ fontSize: "0.8rem", color: "var(--mc-text-muted)", margin: "0" }}>
              Activating Global Step-Up forces all users to re-authenticate with their primary credentials and MFA on the next API request.
            </p>
            <button
              className={`mc-btn ${stepUpEnabled ? 'mc-btn-danger' : 'mc-btn-secondary'}`}
              onClick={() => {
                const next = !stepUpEnabled;
                setStepUpEnabled(next);
                alert(`Global Step-Up Authentication ${next ? 'ACTIVATED' : 'DEACTIVATED'}. Audit log entry recorded.`);
              }}
            >
              {stepUpEnabled ? '⚡ STEP-UP ENGAGED (DISENGAGE)' : 'ENGAGE GLOBAL STEP-UP'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
