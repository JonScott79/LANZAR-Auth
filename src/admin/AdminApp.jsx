import { Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom'
import AdminDashboard from './AdminDashboard.jsx'
import AdminOrganizations from './AdminOrganizations.jsx'
import AdminOrgDetail from './AdminOrgDetail.jsx'
import AdminAnnouncements from './AdminAnnouncements.jsx'
import AdminServices from './AdminServices.jsx'
import './AdminApp.css'

export default function AdminApp({ admin, user, handleSignOut }) {
  const navigate = useNavigate()
  const location = useLocation()

  return (
    <div className="admin-app">
      {/* Top Navbar */}
      <nav className="admin-nav">
        <div className="admin-brand">
          <span className="admin-brand-title">LANZAR ADMIN</span>
          <span className="admin-brand-badge">OPERATIONS CENTER</span>
        </div>
        <div className="admin-nav-links">
          <button className={`admin-nav-link ${location.pathname === '/admin' ? 'active' : ''}`} onClick={() => navigate('/admin')}>Dashboard</button>
          <button className={`admin-nav-link ${location.pathname.startsWith('/admin/orgs') ? 'active' : ''}`} onClick={() => navigate('/admin/orgs')}>Organizations</button>
          <button className={`admin-nav-link ${location.pathname === '/admin/services' ? 'active' : ''}`} onClick={() => navigate('/admin/services')}>Service Catalog</button>
          <button className={`admin-nav-link ${location.pathname === '/admin/announcements' ? 'active' : ''}`} onClick={() => navigate('/admin/announcements')}>Announcements</button>
          <a href="https://tickets.lanzar.me" target="_blank" rel="noopener noreferrer" className="admin-nav-link">Ticket Queue &#8599;</a>
        </div>
        <div className="admin-nav-user">
          <span className="admin-email">{user.email}</span>
          <button className="admin-logout" onClick={handleSignOut}>SIGN OUT</button>
        </div>
      </nav>

      {/* Main Content */}
      <main className="admin-content">
        <Routes>
          <Route path="/" element={<Navigate to="/admin" />} />
          <Route path="/admin" element={<AdminDashboard />} />
          <Route path="/admin/orgs" element={<AdminOrganizations />} />
          <Route path="/admin/orgs/:id/*" element={<AdminOrgDetail />} />
          <Route path="/admin/services" element={<AdminServices />} />
          <Route path="/admin/announcements" element={<AdminAnnouncements admin={admin} user={user} />} />
          <Route path="*" element={<Navigate to="/admin" />} />
        </Routes>
      </main>
    </div>
  )
}
