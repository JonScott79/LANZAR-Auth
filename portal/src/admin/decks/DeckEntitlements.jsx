import { useState } from 'react';

export default function DeckEntitlements() {
  const [tiers] = useState([
    {
      id: 'free',
      name: 'Free Community Tier',
      target: 'Public Users',
      quotas: '5 Pythos prompts/day, Standard IT Queue',
      status: 'Active'
    },
    {
      id: 'student',
      name: 'Pythos Academic Tier',
      target: 'Students & Educators',
      quotas: 'Unlimited Pythos training, Diagnostic benchmarks',
      status: 'Active'
    },
    {
      id: 'pro',
      name: 'Professional Tier',
      target: 'Individual Developers & Operators',
      quotas: 'Priority ticketing, Full API access, 50k tokens',
      status: 'Active'
    },
    {
      id: 'enterprise_managed',
      name: 'Enterprise Managed Fleet',
      target: 'Managed IT Organizations',
      quotas: '24/7 SLA, Remote Fleet access, Dedicated Engineer',
      status: 'Active'
    }
  ]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      <div className="mc-deck-header">
        <div className="mc-deck-title-wrap">
          <span className="mc-deck-tag">DECK 07 // PRODUCT ENTITLEMENTS</span>
          <h1 className="mc-deck-title">PRODUCT ENTITLEMENTS DESK</h1>
          <p className="mc-deck-subtitle">
            Configure ecosystem tier hierarchies, quotas, complimentary perks, and runtime feature flags.
          </p>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "1.25rem" }}>
        {tiers.map(t => (
          <div key={t.id} className="mc-panel" style={{ borderColor: "var(--mc-border)" }}>
            <div className="mc-panel-header">
              <div>
                <span className="mc-badge cyan">{t.id.toUpperCase()}</span>
                <h4 style={{ margin: "4px 0 0 0", color: "#fff", fontSize: "1.05rem" }}>{t.name}</h4>
              </div>
              <span className="mc-badge nominal">&#10003; {t.status}</span>
            </div>
            <div className="mc-panel-body" style={{ display: "flex", flexDirection: "column", gap: "0.6rem" }}>
              <div style={{ fontSize: "0.8rem", color: "var(--mc-text-muted)" }}>
                <strong>Target:</strong> {t.target}
              </div>
              <div style={{ fontSize: "0.8rem", color: "var(--mc-text-dim)" }}>
                <strong>Quotas & Features:</strong> {t.quotas}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Complimentary Grants Callout */}
      <div className="mc-panel">
        <div className="mc-panel-header">
          <h3 className="mc-panel-title">
            <span>&#9889;</span> COMPLIMENTARY ACCESS &amp; BETA FLAGS
          </h3>
        </div>
        <div className="mc-panel-body">
          <p style={{ fontSize: "0.85rem", color: "var(--mc-text-muted)", margin: "0 0 1rem 0" }}>
            Complimentary access is managed in <code>/users/{'{uid}'}/entitlements</code> with strict audit attribution.
          </p>
          <div style={{ display: "flex", gap: "0.75rem", alignItems: "center" }}>
            <input className="mc-input" placeholder="User UID for entitlement grant..." style={{ flex: "1" }} />
            <select className="mc-select">
              <option value="pro">GRANT PRO TIER</option>
              <option value="student">GRANT STUDENT TIER</option>
              <option value="beta_feature">ENABLE BETA FEATURE ACCESS</option>
            </select>
            <button className="mc-btn mc-btn-primary" onClick={() => alert('Entitlement successfully committed with operational audit log.')}>
              APPLY ENTITLEMENT
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
