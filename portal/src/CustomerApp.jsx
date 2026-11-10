import { Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom'
import Dashboard from './pages/Dashboard.jsx'
import Locations from './pages/Locations.jsx'
import Equipment from './pages/Equipment.jsx'
import Users from './pages/Users.jsx'
import Account from './pages/Account.jsx'
import Billing from './pages/Billing.jsx'
import Stella from './components/Stella.jsx'

export default function CustomerApp({ customer, user, handleSignOut }) {
  const navigate = useNavigate()
  const location = useLocation()

  return (
    <div className="portal-app">
      <div className="portal-container">
        {/* Left/Top Column: Stella and Navigation */}
        <aside className="stella-column">
           <Stella user={user} customer={customer} authError={null} />
           
           <nav className="portal-nav">
             <button className={`nav-link ${location.pathname === '/dashboard' || location.pathname === '/' ? 'active' : ''}`} onClick={() => navigate('/dashboard')}>
               ★ Dashboard
             </button>
             <button className={`nav-link ${location.pathname === '/billing' ? 'active' : ''}`} onClick={() => navigate('/billing')}>
               ★ Services &amp; Billing
             </button>
             <button className={`nav-link ${location.pathname === '/locations' ? 'active' : ''}`} onClick={() => navigate('/locations')}>
               ★ Locations
             </button>
             <button className={`nav-link ${location.pathname === '/equipment' ? 'active' : ''}`} onClick={() => navigate('/equipment')}>
               ★ Equipment
             </button>
             <button className={`nav-link ${location.pathname === '/users' ? 'active' : ''}`} onClick={() => navigate('/users')}>
               ★ Users
             </button>
             <button className={`nav-link ${location.pathname === '/account' ? 'active' : ''}`} onClick={() => navigate('/account')}>
               ★ Account
             </button>
             
             <div className="nav-divider"></div>

             <a href="https://tickets.lanzar.me" target="_blank" rel="noopener noreferrer" className="nav-support-link">
               Need Technical Help?<br/>
               <strong>OPEN LANZAR SUPPORT &rarr;</strong>
             </a>

             <a href="https://lanzar.me" className="nav-link" style={{ textDecoration: 'none', display: 'block', textAlign: 'center', marginTop: '0.35rem', fontSize: '0.82rem' }}>
               &larr; Return to LANZAR.me
             </a>

             <button className="nav-button logout" onClick={handleSignOut}>
               Sign Out
             </button>
           </nav>
        </aside>

        {/* Right/Bottom Column: Main Content */}
        <main className="portal-content">
          <header className="portal-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
            <div className="portal-brand">
              <h1>MY LANZAR</h1>
              <span className="org-name">{customer.customerName}</span>
            </div>
            <div style={{ display: 'flex', gap: '1rem', fontSize: '0.85rem', fontWeight: 700 }}>
              <a href="https://it.lanzar.me/tech-pricing.html" target="_blank" rel="noopener noreferrer" style={{ color: 'var(--rocket-orange, #f46b45)', textDecoration: 'none' }}>IT Support Plans &#8599;</a>
              <a href="https://lanzar.me" style={{ color: 'var(--deep-navy, #102a43)', textDecoration: 'none' }}>LANZAR.me &rarr;</a>
            </div>
          </header>

          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" />} />
            <Route path="/dashboard" element={<Dashboard customer={customer} />} />
            <Route path="/billing" element={<Billing customer={customer} user={user} />} />
            <Route path="/locations" element={<Locations customer={customer} />} />
            <Route path="/equipment" element={<Equipment customer={customer} />} />
            <Route path="/users" element={<Users customer={customer} />} />
            <Route path="/account" element={<Account customer={customer} user={user} />} />
            <Route path="*" element={<Navigate to="/dashboard" />} />
          </Routes>
        </main>
      </div>
    </div>
  )
}
