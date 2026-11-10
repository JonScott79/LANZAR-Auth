import { useState, useEffect } from 'react'
import { getFirestore, collection, getDocs, query, where, limit } from 'firebase/firestore'
import { useNavigate } from 'react-router-dom'
import app from '../firebase/config.js'

const db = getFirestore(app)

export default function AdminDashboard() {
  const navigate = useNavigate()
  const [stats, setStats] = useState({
    orgs: '-',
    users: '-',
    tickets: '-',
  })

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const orgsSnap = await getDocs(collection(db, 'accounts'))
        const usersSnap = await getDocs(query(collection(db, 'users'), where('active', '==', true)))
        const ticketsSnap = await getDocs(query(collection(db, 'tickets'), where('status', 'in', ['PENDING', 'IN_PROGRESS', 'MORE_INFO'])))

        setStats({
          orgs: orgsSnap.size,
          users: usersSnap.size,
          tickets: ticketsSnap.size,
        })
      } catch (err) {
        console.error('Error fetching admin stats', err)
      }
    }
    fetchStats()
  }, [])

  return (
    <div>
      <div className="admin-header">
        <h1>Overview</h1>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1.5rem', marginBottom: '2rem' }}>
        <div className="admin-card" style={{ marginBottom: 0, textAlign: 'center' }}>
          <div style={{ fontSize: '3rem', fontWeight: 800, color: '#2a4365', lineHeight: 1 }}>{stats.orgs}</div>
          <div style={{ color: '#718096', fontSize: '0.9rem', marginTop: '0.5rem', fontWeight: 'bold' }}>ORGANIZATIONS</div>
        </div>
        <div className="admin-card" style={{ marginBottom: 0, textAlign: 'center' }}>
          <div style={{ fontSize: '3rem', fontWeight: 800, color: '#2a4365', lineHeight: 1 }}>{stats.users}</div>
          <div style={{ color: '#718096', fontSize: '0.9rem', marginTop: '0.5rem', fontWeight: 'bold' }}>ACTIVE USERS</div>
        </div>
        <div className="admin-card" style={{ marginBottom: 0, textAlign: 'center' }}>
          <div style={{ fontSize: '3rem', fontWeight: 800, color: '#f46b45', lineHeight: 1 }}>{stats.tickets}</div>
          <div style={{ color: '#718096', fontSize: '0.9rem', marginTop: '0.5rem', fontWeight: 'bold' }}>OPEN TICKETS</div>
        </div>
        <div className="admin-card" style={{ marginBottom: 0, textAlign: 'center' }}>
          <div style={{ fontSize: '3rem', fontWeight: 800, color: '#2a4365', lineHeight: 1 }}>—</div>
          <div style={{ color: '#718096', fontSize: '0.9rem', marginTop: '0.5rem', fontWeight: 'bold' }}>SERVICES</div>
        </div>
      </div>

      <div className="admin-card">
        <h2 style={{ marginTop: 0, marginBottom: '1.5rem', fontSize: '1.25rem' }}>Quick Actions</h2>
        <div style={{ display: 'flex', gap: '1rem' }}>
          <button className="admin-btn-secondary" onClick={() => navigate('/admin/orgs')}>Manage Organizations</button>
          <button className="admin-btn-secondary" onClick={() => navigate('/admin/announcements')}>Send Announcement</button>
          <a href="https://tickets.lanzar.me" target="_blank" rel="noopener noreferrer" style={{ textDecoration: 'none' }}>
            <button className="admin-btn-secondary">View Ticket Queue</button>
          </a>
        </div>
      </div>
    </div>
  )
}
