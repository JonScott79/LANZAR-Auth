import { useState, useEffect } from 'react';
import { fetchUsers, grantFounderDesignation, revokeFounderDesignation } from './adminApi.js';

export default function DeckFounders() {
  const [foundersList, setFoundersList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Award Modal State
  const [awardModal, setAwardModal] = useState({
    isOpen: false,
    uid: '',
    programId: 'id',
    founderNumber: '001',
    title: 'LANZAR ID FOUNDER',
    grantReason: '',
    isSubmitting: false
  });

  // Revoke Modal State
  const [revokeModal, setRevokeModal] = useState({
    isOpen: false,
    uid: '',
    programId: '',
    userEmail: '',
    reason: '',
    isSubmitting: false
  });

  const programs = [
    { id: 'id', title: 'LANZAR ID Founder', color: 'gold', desc: 'Foundational universal account holder of the LANZAR identity architecture.' },
    { id: 'pythos', title: 'Pythos Founder', color: 'cyan', desc: 'Pioneering patron of autonomous adaptive mathematics AI.' },
    { id: 'portal', title: 'Portal Founder', color: 'emerald', desc: 'Early enterprise partner and client portal pioneer.' },
    { id: 'traveling', title: 'Traveling Founder', color: 'amber', desc: 'Nomadic fleet and cross-sector field operator.' },
    { id: 'threadline', title: 'Threadline Founder', color: 'rose', desc: 'Foundational software workflow engineering collaborator.' }
  ];

  const loadFounders = async () => {
    try {
      setLoading(true);
      setError(null);
      // Fetch users and find those with derivedBadges or active founders
      const data = await fetchUsers('', '', 100);
      const list = (data.users || []).filter(u => u.derivedBadges && u.derivedBadges.length > 0);
      setFoundersList(list);
    } catch (err) {
      console.error('Failed to load founders list:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadFounders();
  }, []);

  const handleProgramSelect = (programId) => {
    const p = programs.find(item => item.id === programId);
    setAwardModal(prev => ({
      ...prev,
      programId,
      title: p ? p.title.toUpperCase() : 'FOUNDER'
    }));
  };

  const handleAwardSubmit = async (e) => {
    e.preventDefault();
    const { uid, programId, founderNumber, title, grantReason } = awardModal;
    if (!uid || !grantReason) {
      alert('Please fill in user UID and grant justification.');
      return;
    }

    try {
      setAwardModal(prev => ({ ...prev, isSubmitting: true }));
      await grantFounderDesignation(uid, programId, founderNumber, title, grantReason);
      alert(`Founder designation successfully awarded to ${uid}!`);
      setAwardModal({ isOpen: false, uid: '', programId: 'id', founderNumber: '001', title: 'LANZAR ID FOUNDER', grantReason: '', isSubmitting: false });
      await loadFounders();
    } catch (err) {
      alert(`Award failed: ${err.message}`);
      setAwardModal(prev => ({ ...prev, isSubmitting: false }));
    }
  };

  const handleRevokeSubmit = async (e) => {
    e.preventDefault();
    const { uid, programId, reason } = revokeModal;
    if (!reason) {
      alert('Operational reason is required for revocation.');
      return;
    }

    try {
      setRevokeModal(prev => ({ ...prev, isSubmitting: true }));
      await revokeFounderDesignation(uid, programId, reason);
      alert(`Founder designation ${programId} revoked for ${uid}.`);
      setRevokeModal({ isOpen: false, uid: '', programId: '', userEmail: '', reason: '', isSubmitting: false });
      await loadFounders();
    } catch (err) {
      alert(`Revocation failed: ${err.message}`);
      setRevokeModal(prev => ({ ...prev, isSubmitting: false }));
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      <div className="mc-deck-header">
        <div className="mc-deck-title-wrap">
          <span className="mc-deck-tag">DECK 06 // FOUNDER PROGRAMS LEDGER</span>
          <h1 className="mc-deck-title">FOUNDER PROGRAMS LEDGER</h1>
          <p className="mc-deck-subtitle">
            Authoritative product-scoped founder awards, sequential numbering, and derived profile summaries.
          </p>
        </div>
        <div className="mc-deck-actions">
          <button className="mc-btn mc-btn-primary" onClick={() => setAwardModal(prev => ({ ...prev, isOpen: true }))}>
            + AWARD FOUNDER DESIGNATION
          </button>
        </div>
      </div>

      {error && (
        <div style={{ padding: "1rem", background: "var(--mc-rose-dim)", border: "1px solid var(--mc-rose)", borderRadius: "6px", color: "var(--mc-rose)", fontFamily: "var(--mc-font-mono)", fontSize: "0.82rem" }}>
          FAILED TO QUERY FOUNDER LEDGER: {error}
        </div>
      )}

      {/* Program Pillar Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: "1rem" }}>
        {programs.map(p => (
          <div key={p.id} className={`mc-metric-card ${p.color}`}>
            <span className="mc-metric-label">{p.id.toUpperCase()} SECTOR</span>
            <div style={{ fontSize: "1.25rem", fontWeight: "800", color: "#fff", margin: "4px 0" }}>{p.title}</div>
            <p style={{ fontSize: "0.72rem", color: "var(--mc-text-muted)", lineHeight: "1.4", margin: "0" }}>
              {p.desc}
            </p>
          </div>
        ))}
      </div>

      {/* Founder Roster Table */}
      <div className="mc-panel">
        <div className="mc-panel-header">
          <h3 className="mc-panel-title">
            <span>🎖</span> ACTIVE FOUNDER ROSTER ({foundersList.length})
          </h3>
          <button className="mc-btn mc-btn-secondary" style={{ padding: "4px 10px", fontSize: "0.72rem" }} onClick={loadFounders}>
            &#8635; REFRESH LEDGER
          </button>
        </div>
        <div className="mc-panel-body" style={{ padding: "0" }}>
          <div className="mc-table-container" style={{ border: "none" }}>
            <table className="mc-table">
              <thead>
                <tr>
                  <th>FOUNDER IDENTITIES</th>
                  <th>EMAIL</th>
                  <th>ACTIVE FOUNDER BADGES</th>
                  <th>STATUS</th>
                  <th style={{ textAlign: "right" }}>OPERATIONS</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan="5" style={{ textAlign: "center", padding: "2rem", color: "var(--mc-text-dim)" }}>
                      Consulting authoritative founder subcollections...
                    </td>
                  </tr>
                ) : foundersList.length === 0 ? (
                  <tr>
                    <td colSpan="5" style={{ textAlign: "center", padding: "2rem", color: "var(--mc-text-dim)" }}>
                      No active founder designations found. Click "+ AWARD FOUNDER DESIGNATION" to create one.
                    </td>
                  </tr>
                ) : (
                  foundersList.map(u => (
                    <tr key={u.uid}>
                      <td>
                        <div style={{ fontWeight: "700", color: "#fff" }}>{u.displayName || 'Unnamed Operator'}</div>
                        <div style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.68rem", color: "var(--mc-text-dim)" }}>
                          {u.uid}
                        </div>
                      </td>
                      <td style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.8rem" }}>{u.email}</td>
                      <td>
                        <div style={{ display: "flex", gap: "0.35rem", flexWrap: "wrap" }}>
                          {u.derivedBadges.map((badge, idx) => (
                            <span key={idx} className="mc-badge gold">{badge}</span>
                          ))}
                        </div>
                      </td>
                      <td>
                        <span className="mc-badge nominal">&#10003; VERIFIED AUTHORITATIVE</span>
                      </td>
                      <td style={{ textAlign: "right" }}>
                        <button
                          className="mc-btn mc-btn-danger"
                          style={{ padding: "3px 8px", fontSize: "0.7rem" }}
                          onClick={() => setRevokeModal({
                            isOpen: true,
                            uid: u.uid,
                            programId: 'id',
                            userEmail: u.email,
                            reason: '',
                            isSubmitting: false
                          })}
                        >
                          REVOKE...
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

      {/* Award Designation Modal */}
      {awardModal.isOpen && (
        <div className="mc-modal-backdrop" onClick={() => setAwardModal(prev => ({ ...prev, isOpen: false }))}>
          <div className="mc-modal" style={{ borderColor: "var(--mc-gold)" }} onClick={e => e.stopPropagation()}>
            <div className="mc-modal-header" style={{ background: "rgba(255, 215, 0, 0.1)", borderColor: "rgba(255, 215, 0, 0.3)" }}>
              <span style={{ fontSize: "1.2rem", color: "var(--mc-gold)" }}>🎖</span>
              <h3 className="mc-modal-title" style={{ color: "var(--mc-gold)" }}>AWARD FOUNDER DESIGNATION</h3>
            </div>
            <form onSubmit={handleAwardSubmit}>
              <div className="mc-modal-body">
                <div>
                  <label style={{ fontSize: "0.75rem", fontFamily: "var(--mc-font-mono)", color: "var(--mc-text-dim)" }}>
                    TARGET USER UID:
                  </label>
                  <input
                    className="mc-input"
                    style={{ width: "100%", marginTop: "4px" }}
                    placeholder="Firebase Auth UID"
                    required
                    value={awardModal.uid}
                    onChange={e => setAwardModal(prev => ({ ...prev, uid: e.target.value }))}
                  />
                </div>

                <div>
                  <label style={{ fontSize: "0.75rem", fontFamily: "var(--mc-font-mono)", color: "var(--mc-text-dim)" }}>
                    SELECT PRODUCT PROGRAM:
                  </label>
                  <select
                    className="mc-select"
                    style={{ width: "100%", marginTop: "4px" }}
                    value={awardModal.programId}
                    onChange={e => handleProgramSelect(e.target.value)}
                  >
                    {programs.map(p => (
                      <option key={p.id} value={p.id}>{p.title}</option>
                    ))}
                  </select>
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: "0.75rem" }}>
                  <div>
                    <label style={{ fontSize: "0.75rem", fontFamily: "var(--mc-font-mono)", color: "var(--mc-text-dim)" }}>
                      NUMBER:
                    </label>
                    <input
                      className="mc-input"
                      style={{ width: "100%", marginTop: "4px" }}
                      placeholder="001"
                      value={awardModal.founderNumber}
                      onChange={e => setAwardModal(prev => ({ ...prev, founderNumber: e.target.value }))}
                    />
                  </div>
                  <div>
                    <label style={{ fontSize: "0.75rem", fontFamily: "var(--mc-font-mono)", color: "var(--mc-text-dim)" }}>
                      BADGE TITLE:
                    </label>
                    <input
                      className="mc-input"
                      style={{ width: "100%", marginTop: "4px" }}
                      value={awardModal.title}
                      onChange={e => setAwardModal(prev => ({ ...prev, title: e.target.value }))}
                    />
                  </div>
                </div>

                <div>
                  <label style={{ fontSize: "0.75rem", fontFamily: "var(--mc-font-mono)", color: "var(--mc-text-dim)" }}>
                    MANDATORY OPERATIONAL JUSTIFICATION:
                  </label>
                  <input
                    className="mc-input"
                    style={{ width: "100%", marginTop: "4px" }}
                    placeholder="e.g. Founding patron and early tester"
                    required
                    value={awardModal.grantReason}
                    onChange={e => setAwardModal(prev => ({ ...prev, grantReason: e.target.value }))}
                  />
                </div>
              </div>

              <div className="mc-modal-footer">
                <button
                  type="button"
                  className="mc-btn mc-btn-secondary"
                  onClick={() => setAwardModal(prev => ({ ...prev, isOpen: false }))}
                >
                  CANCEL
                </button>
                <button
                  type="submit"
                  className="mc-btn mc-btn-primary"
                  disabled={awardModal.isSubmitting}
                >
                  {awardModal.isSubmitting ? 'AWARDING...' : 'COMMIT DESIGNATION'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Revocation Modal */}
      {revokeModal.isOpen && (
        <div className="mc-modal-backdrop" onClick={() => setRevokeModal(prev => ({ ...prev, isOpen: false }))}>
          <div className="mc-modal" onClick={e => e.stopPropagation()}>
            <div className="mc-modal-header">
              <span style={{ fontSize: "1.2rem", color: "var(--mc-rose)" }}>&#9888;</span>
              <h3 className="mc-modal-title">REVOKE FOUNDER DESIGNATION</h3>
            </div>
            <form onSubmit={handleRevokeSubmit}>
              <div className="mc-modal-body">
                <div>
                  Revoking founder for: <strong>{revokeModal.userEmail}</strong> ({revokeModal.uid})
                </div>

                <div>
                  <label style={{ fontSize: "0.75rem", fontFamily: "var(--mc-font-mono)", color: "var(--mc-text-dim)" }}>
                    PROGRAM TO REVOKE:
                  </label>
                  <select
                    className="mc-select"
                    style={{ width: "100%", marginTop: "4px" }}
                    value={revokeModal.programId}
                    onChange={e => setRevokeModal(prev => ({ ...prev, programId: e.target.value }))}
                  >
                    {programs.map(p => (
                      <option key={p.id} value={p.id}>{p.title}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label style={{ fontSize: "0.75rem", fontFamily: "var(--mc-font-mono)", color: "var(--mc-text-dim)" }}>
                    MANDATORY REVOCATION REASON:
                  </label>
                  <input
                    className="mc-input"
                    style={{ width: "100%", marginTop: "4px" }}
                    placeholder="e.g. Inadvertent grant during rehearsal"
                    required
                    value={revokeModal.reason}
                    onChange={e => setRevokeModal(prev => ({ ...prev, reason: e.target.value }))}
                  />
                </div>
              </div>

              <div className="mc-modal-footer">
                <button
                  type="button"
                  className="mc-btn mc-btn-secondary"
                  onClick={() => setRevokeModal(prev => ({ ...prev, isOpen: false }))}
                >
                  CANCEL
                </button>
                <button
                  type="submit"
                  className="mc-btn mc-btn-danger"
                  disabled={revokeModal.isSubmitting}
                >
                  {revokeModal.isSubmitting ? 'REVOKING...' : 'CONFIRM REVOCATION'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
