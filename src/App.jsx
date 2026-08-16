import { useState, useEffect } from 'react'
import { onAuthStateChanged } from 'firebase/auth'
import { auth, signOutUser } from './firebase/auth.js'
import Login from './pages/Login.jsx'
import './App.css'

function App() {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (firebaseUser) => {
      setUser(firebaseUser)
      setLoading(false)
      
      if (firebaseUser) {
        // Handle OAuth Redirect Logic if client_id is present
        const params = new URLSearchParams(window.location.search)
        const redirectUri = params.get('redirect_uri')
        const clientId = params.get('client_id')
        
        if (redirectUri && clientId) {
          console.log(`[LANZAR ID] Redirecting to ${redirectUri} for client ${clientId}`)
          // Mock Authorization Code Generation
          const mockCode = 'lanzar_auth_code_' + Math.random().toString(36).substring(7)
          setTimeout(() => {
            window.location.href = `${redirectUri}?code=${mockCode}`
          }, 1500) // Brief delay to show the identity screen
        }
      }
    })
    return () => unsubscribe()
  }, [])

  if (loading) {
    return (
      <main className="loading-screen">
        <p>Connecting to LANZAR Identity...</p>
      </main>
    )
  }

  if (!user) {
    return (
      <div className="portal-app">
        <div className="portal-container" style={{ alignItems: 'center', justifyContent: 'center' }}>
          <Login />
        </div>
      </div>
    )
  }

  // Identity Dashboard (If accessed directly without a redirect_uri)
  return (
    <div className="portal-app">
      <nav className="admin-nav" style={{ padding: '1rem 2rem', background: 'var(--deep-navy)', color: 'var(--color-cream)', display: 'flex', justifyContent: 'space-between' }}>
        <div className="admin-brand">
          <span className="admin-brand-title">LANZAR ID</span>
          <span className="admin-brand-badge">IDENTITY CENTER</span>
        </div>
        <div className="admin-nav-user" style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
          <span className="admin-email">{user.email}</span>
          <button className="admin-logout" onClick={signOutUser} style={{ background: 'var(--rocket-orange)', color: 'white', border: 'none', padding: '0.5rem 1rem', borderRadius: '4px', cursor: 'pointer', fontWeight: 'bold' }}>SIGN OUT</button>
        </div>
      </nav>

      <main className="portal-container" style={{ padding: '3rem', maxWidth: '800px', margin: '0 auto' }}>
        <h1 style={{ fontFamily: 'var(--font-heading)', color: 'var(--deep-navy)', fontSize: '2.5rem', marginBottom: '1rem' }}>Your LANZAR Identity</h1>
        <p style={{ fontSize: '1.2rem', color: 'var(--text-secondary)', marginBottom: '2rem' }}>You are securely authenticated across the LANZAR ecosystem.</p>
        
        <div style={{ background: 'white', border: '4px solid var(--deep-navy)', borderRadius: '8px', padding: '2rem', boxShadow: '8px 8px 0px var(--rocket-orange)' }}>
          <h2 style={{ fontFamily: 'var(--font-heading)', color: 'var(--rocket-orange)', marginBottom: '1rem' }}>Active Session</h2>
          <p><strong>Account:</strong> {user.email}</p>
          <p><strong>UID:</strong> {user.uid}</p>
          <p><strong>Status:</strong> Verified</p>
          
          <div style={{ marginTop: '2rem', borderTop: '2px solid var(--soft-gray)', paddingTop: '2rem' }}>
            <h3 style={{ fontFamily: 'var(--font-heading)', color: 'var(--deep-navy)', marginBottom: '1rem' }}>Connected Applications</h3>
            <ul style={{ listStyle: 'none', padding: 0, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <li style={{ display: 'flex', justifyContent: 'space-between', padding: '1rem', background: 'var(--bg-primary)', borderRadius: '4px' }}>
                <strong>LANZAR Portal</strong>
                <a href="https://portal.lanzar.me" target="_blank" rel="noopener noreferrer" style={{ color: 'var(--retro-teal)', fontWeight: 'bold', textDecoration: 'none' }}>Open &#8599;</a>
              </li>
              <li style={{ display: 'flex', justifyContent: 'space-between', padding: '1rem', background: 'var(--bg-primary)', borderRadius: '4px' }}>
                <strong>LANZAR Tickets</strong>
                <a href="https://tickets.lanzar.me" target="_blank" rel="noopener noreferrer" style={{ color: 'var(--retro-teal)', fontWeight: 'bold', textDecoration: 'none' }}>Open &#8599;</a>
              </li>
            </ul>
          </div>
        </div>
      </main>
    </div>
  )
}

export default App
