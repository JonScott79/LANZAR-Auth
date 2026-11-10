import { useState, useEffect } from 'react';
import { Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom';

// Mission Control Core Decks
import DeckOverview from './decks/DeckOverview.jsx';
import DeckIdentities from './decks/DeckIdentities.jsx';
import DeckSecurity from './decks/DeckSecurity.jsx';
import DeckApplications from './decks/DeckApplications.jsx';
import DeckFounders from './decks/DeckFounders.jsx';
import DeckEntitlements from './decks/DeckEntitlements.jsx';
import DeckTelemetry from './decks/DeckTelemetry.jsx';
import DeckAudit from './decks/DeckAudit.jsx';
import DeckConfig from './decks/DeckConfig.jsx';
import CommandPalette from './decks/CommandPalette.jsx';

// Existing Specialized Operational Utilities
import AdminOrganizations from './AdminOrganizations.jsx';
import AdminOrgDetail from './AdminOrgDetail.jsx';
import AdminAnnouncements from './AdminAnnouncements.jsx';
import AdminServices from './AdminServices.jsx';
import AdminNewsletter from './AdminNewsletter.jsx';
import AdminSupportVerification from './AdminSupportVerification.jsx';
import AdminVirtualTerminal from './AdminVirtualTerminal.jsx';
import AdminSupportGuides from './AdminSupportGuides.jsx';

// Aerospace Design System
import './MissionControl.css';

export default function AdminApp({ admin, user, handleSignOut }) {
  const navigate = useNavigate();
  const location = useLocation();

  // UTC System Clock
  const [utcTime, setUtcTime] = useState('');
  const [paletteOpen, setPaletteOpen] = useState(false);

  useEffect(() => {
    function updateClock() {
      const now = new Date();
      setUtcTime(now.toUTCString().replace('GMT', 'UTC'));
    }
    updateClock();
    const interval = setInterval(updateClock, 1000);
    return () => clearInterval(interval);
  }, []);

  // Global Keyboard Shortcut for Command Palette (Cmd/Ctrl + K)
  useEffect(() => {
    function handleKeyDown(e) {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setPaletteOpen(prev => !prev);
      }
    }
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const operatorInitial = ((user?.email ? user.email.charAt(0) : 'A')).toUpperCase();

  return (
    <div className="mc-container">
      {/* TOP TELEMETRY BAR */}
      <header className="mc-topbar">
        <div className="mc-topbar-left">
          <div className="mc-brand">
            <div className="mc-brand-orb"></div>
            <span className="mc-brand-text">LANZAR</span>
            <span className="mc-brand-badge">MISSION CONTROL</span>
          </div>
          <div className="mc-telemetry-pill">
            <span style={{ color: "var(--mc-emerald)", fontSize: "0.8em" }}>&#9679;</span>
            <span>TELEMETRY NOMINAL</span>
          </div>
        </div>

        <div className="mc-topbar-center">
          <button className="mc-search-trigger" onClick={() => setPaletteOpen(true)}>
            <span style={{ color: "var(--mc-gold)" }}>&#9737;</span>
            <span>Quick Jump (Decks, Users, Logs)...</span>
            <span className="mc-kbd-shortcut">Cmd/Ctrl + K</span>
          </button>
        </div>

        <div className="mc-topbar-right">
          <div className="mc-clock">{utcTime}</div>
          <div className="mc-operator-card">
            <div className="mc-operator-avatar">{operatorInitial}</div>
            <span className="mc-operator-email">{user?.email || 'operator@lanzar.me'}</span>
          </div>
          <button className="mc-btn-signout" onClick={handleSignOut}>
            SIGN OUT
          </button>
        </div>
      </header>

      {/* ORBITAL COMMAND RAIL (COLLAPSIBLE SIDEBAR) */}
      <nav className="mc-rail">
        {/* Core Identity Decks */}
        <div className="mc-rail-section">
          <div className="mc-rail-heading">OPERATIONAL DECKS</div>

          <button
            className={`mc-rail-link ${location.pathname === '/admin' ? 'active' : ''}`}
            onClick={() => navigate('/admin')}
          >
            <span className="mc-rail-icon">🛰</span>
            <span>Overview Radar</span>
          </button>

          <button
            className={`mc-rail-link ${location.pathname === '/admin/identities' ? 'active' : ''}`}
            onClick={() => navigate('/admin/identities')}
          >
            <span className="mc-rail-icon">🔑</span>
            <span>Identity Explorer</span>
          </button>

          <button
            className={`mc-rail-link ${location.pathname === '/admin/security' ? 'active' : ''}`}
            onClick={() => navigate('/admin/security')}
          >
            <span className="mc-rail-icon">🛡</span>
            <span>Security Center</span>
          </button>

          <button
            className={`mc-rail-link ${location.pathname === '/admin/apps' ? 'active' : ''}`}
            onClick={() => navigate('/admin/apps')}
          >
            <span className="mc-rail-icon">📦</span>
            <span>App Registry</span>
          </button>

          <button
            className={`mc-rail-link ${location.pathname.startsWith('/admin/orgs') ? 'active' : ''}`}
            onClick={() => navigate('/admin/orgs')}
          >
            <span className="mc-rail-icon">🏢</span>
            <span>Organization Desk</span>
          </button>

          <button
            className={`mc-rail-link ${location.pathname === '/admin/founders' ? 'active' : ''}`}
            onClick={() => navigate('/admin/founders')}
          >
            <span className="mc-rail-icon">🎖</span>
            <span>Founder Programs</span>
          </button>

          <button
            className={`mc-rail-link ${location.pathname === '/admin/entitlements' ? 'active' : ''}`}
            onClick={() => navigate('/admin/entitlements')}
          >
            <span className="mc-rail-icon">⚡</span>
            <span>Entitlements</span>
          </button>

          <button
            className={`mc-rail-link ${location.pathname === '/admin/telemetry' ? 'active' : ''}`}
            onClick={() => navigate('/admin/telemetry')}
          >
            <span className="mc-rail-icon">📡</span>
            <span>Telemetry</span>
          </button>

          <button
            className={`mc-rail-link ${location.pathname === '/admin/audit' ? 'active' : ''}`}
            onClick={() => navigate('/admin/audit')}
          >
            <span className="mc-rail-icon">📜</span>
            <span>Audit Center</span>
          </button>

          <button
            className={`mc-rail-link ${location.pathname === '/admin/config' ? 'active' : ''}`}
            onClick={() => navigate('/admin/config')}
          >
            <span className="mc-rail-icon">⚙</span>
            <span>System Config</span>
          </button>
        </div>

        {/* Specialized Operational Tools */}
        <div className="mc-rail-section" style={{ borderTop: "1px solid var(--mc-border)", marginTop: "0.5rem" }}>
          <div className="mc-rail-heading">SPECIALIZED OPS</div>

          <button
            className={`mc-rail-link ${location.pathname === '/admin/terminal' ? 'active' : ''}`}
            onClick={() => navigate('/admin/terminal')}
          >
            <span className="mc-rail-icon">💳</span>
            <span>Virtual Terminal</span>
          </button>

          <button
            className={`mc-rail-link ${location.pathname === '/admin/guides' ? 'active' : ''}`}
            onClick={() => navigate('/admin/guides')}
          >
            <span className="mc-rail-icon">📖</span>
            <span>Tech Guides</span>
          </button>

          <button
            className={`mc-rail-link ${location.pathname === '/admin/support' ? 'active' : ''}`}
            onClick={() => navigate('/admin/support')}
          >
            <span className="mc-rail-icon">📞</span>
            <span>Caller Verification</span>
          </button>

          <button
            className={`mc-rail-link ${location.pathname === '/admin/services' ? 'active' : ''}`}
            onClick={() => navigate('/admin/services')}
          >
            <span className="mc-rail-icon">🛠</span>
            <span>Service Catalog</span>
          </button>

          <button
            className={`mc-rail-link ${location.pathname === '/admin/announcements' ? 'active' : ''}`}
            onClick={() => navigate('/admin/announcements')}
          >
            <span className="mc-rail-icon">📢</span>
            <span>Announcements</span>
          </button>

          <button
            className={`mc-rail-link ${location.pathname === '/admin/newsletter' ? 'active' : ''}`}
            onClick={() => navigate('/admin/newsletter')}
          >
            <span className="mc-rail-icon">📰</span>
            <span>Mailing List</span>
          </button>
        </div>

        {/* External Ecosystem Links */}
        <div className="mc-rail-section" style={{ borderTop: "1px solid var(--mc-border)", marginTop: "0.5rem" }}>
          <div className="mc-rail-heading">ECOSYSTEM HUBS</div>
          <a href="https://tickets.lanzar.me" target="_blank" rel="noopener noreferrer" className="mc-rail-link">
            <span className="mc-rail-icon">↗</span>
            <span>Ticket Queue</span>
          </a>
          <a href="https://lanzar.me" target="_blank" rel="noopener noreferrer" className="mc-rail-link">
            <span className="mc-rail-icon">↗</span>
            <span>LANZAR Mothership</span>
          </a>
        </div>
      </nav>

      {/* MAIN COMMAND WORKSPACE */}
      <main className="mc-workspace">
        <Routes>
          <Route path="/" element={<Navigate to="/admin" />} />
          <Route path="/admin" element={<DeckOverview />} />
          <Route path="/admin/identities" element={<DeckIdentities />} />
          <Route path="/admin/security" element={<DeckSecurity />} />
          <Route path="/admin/apps" element={<DeckApplications />} />
          <Route path="/admin/orgs" element={<AdminOrganizations />} />
          <Route path="/admin/orgs/:id/*" element={<AdminOrgDetail />} />
          <Route path="/admin/founders" element={<DeckFounders />} />
          <Route path="/admin/entitlements" element={<DeckEntitlements />} />
          <Route path="/admin/telemetry" element={<DeckTelemetry />} />
          <Route path="/admin/audit" element={<DeckAudit />} />
          <Route path="/admin/config" element={<DeckConfig />} />

          {/* Operational Tools */}
          <Route path="/admin/terminal" element={<AdminVirtualTerminal admin={admin} user={user} />} />
          <Route path="/admin/guides" element={<AdminSupportGuides admin={admin} user={user} />} />
          <Route path="/admin/support" element={<AdminSupportVerification admin={admin} user={user} />} />
          <Route path="/admin/services" element={<AdminServices />} />
          <Route path="/admin/announcements" element={<AdminAnnouncements admin={admin} user={user} />} />
          <Route path="/admin/newsletter" element={<AdminNewsletter admin={admin} user={user} />} />

          <Route path="*" element={<Navigate to="/admin" />} />
        </Routes>
      </main>

      {/* GLOBAL COMMAND PALETTE (CMD + K) */}
      <CommandPalette isOpen={paletteOpen} onClose={() => setPaletteOpen(false)} />
    </div>
  );
}
