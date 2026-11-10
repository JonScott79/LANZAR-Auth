import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

export default function CommandPalette({ isOpen, onClose }) {
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const navigate = useNavigate();

  const commands = [
    { title: 'Operations Overview', desc: 'Sector Radar, Token Velocity, Active Sessions', path: '/admin', icon: '🛰' },
    { title: 'Identity Explorer', desc: 'Search, inspect profiles, badges, sessions, and status', path: '/admin/identities', icon: '🔑' },
    { title: 'Security Center', desc: 'MFA adoption, lockout desk, emergency dual-admin resets', path: '/admin/security', icon: '🛡' },
    { title: 'Application Registry', desc: 'Registered OAuth 2.0 / PKCE clients & redirect whitelists', path: '/admin/apps', icon: '📦' },
    { title: 'Organization Desk', desc: 'Multi-tenancy partitions and client organizations', path: '/admin/orgs', icon: '🏢' },
    { title: 'Founder Programs Ledger', desc: 'Authoritative badges and sequential founder roster', path: '/admin/founders', icon: '🎖' },
    { title: 'Product Entitlements Desk', desc: 'Service tiers, quotas, and complimentary perks', path: '/admin/entitlements', icon: '⚡' },
    { title: 'Infrastructure Telemetry', desc: 'Health gauges, Firebase latency, container metrics', path: '/admin/telemetry', icon: '📡' },
    { title: 'Audit Center', desc: 'Immutable tamper-resistant security stream', path: '/admin/audit', icon: '📜' },
    { title: 'System Configuration', desc: 'Operational parameters, rate limits, and staged SMS', path: '/admin/config', icon: '⚙' },
    { title: 'Virtual Terminal', desc: 'Credit card charge terminal & billing ops', path: '/admin/terminal', icon: '💳' },
    { title: 'Tech Guides & Triage', desc: 'Operator troubleshooting SOPs and playbooks', path: '/admin/guides', icon: '📖' },
    { title: 'Caller Verification', desc: 'Support phone verification and security challenge', path: '/admin/support', icon: '📞' },
    { title: 'Mailing List & Dispatch', desc: 'The Dispatch newsletter subscriber desk', path: '/admin/newsletter', icon: '📰' }
  ];

  const filtered = commands.filter(c => 
    c.title.toLowerCase().includes(query.toLowerCase()) || 
    c.desc.toLowerCase().includes(query.toLowerCase())
  );

  useEffect(() => {
    setSelectedIndex(0);
  }, [query]);

  useEffect(() => {
    function handleKeyDown(e) {
      if (!isOpen) return;

      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setSelectedIndex(prev => (prev + 1) % (filtered.length || 1));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setSelectedIndex(prev => (prev - 1 + (filtered.length || 1)) % (filtered.length || 1));
      } else if (e.key === 'Enter') {
        e.preventDefault();
        if (filtered[selectedIndex]) {
          navigate(filtered[selectedIndex].path);
          onClose();
        }
      } else if (e.key === 'Escape') {
        onClose();
      }
    }

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, filtered, selectedIndex, navigate, onClose]);

  if (!isOpen) return null;

  return (
    <div className="mc-palette-backdrop" onClick={onClose}>
      <div className="mc-palette" onClick={e => e.stopPropagation()}>
        <div className="mc-palette-search">
          <span style={{ color: "var(--mc-gold)", fontSize: "1.1rem" }}>&#9737;</span>
          <input
            className="mc-palette-input"
            autoFocus
            placeholder="Type a command or jump to operational deck..."
            value={query}
            onChange={e => setQuery(e.target.value)}
          />
          <span className="mc-kbd-shortcut">ESC</span>
        </div>

        <div className="mc-palette-results">
          {filtered.length === 0 ? (
            <div style={{ padding: "1.5rem", textAlign: "center", color: "var(--mc-text-dim)", fontSize: "0.85rem" }}>
              No matching operational decks found.
            </div>
          ) : (
            filtered.map((item, idx) => (
              <div
                key={item.path}
                className={`mc-palette-item ${idx === selectedIndex ? 'selected' : ''}`}
                onClick={() => {
                  navigate(item.path);
                  onClose();
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
                  <span style={{ fontSize: "1.1rem" }}>{item.icon}</span>
                  <div>
                    <div style={{ fontWeight: "700", fontSize: "0.88rem" }}>{item.title}</div>
                    <div style={{ fontSize: "0.72rem", color: "var(--mc-text-muted)" }}>{item.desc}</div>
                  </div>
                </div>
                <span style={{ fontFamily: "var(--mc-font-mono)", fontSize: "0.7rem", color: "var(--mc-cyan)" }}>
                  {item.path}
                </span>
              </div>
            ))
          )}
        </div>

        <div className="mc-palette-footer">
          <span>&uarr;&darr; Navigate</span>
          <span>&crarr; Select</span>
          <span>ESC Close</span>
        </div>
      </div>
    </div>
  );
}
