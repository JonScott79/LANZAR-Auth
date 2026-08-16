import { useState, useEffect } from 'react'
import { getFirestore, collection, getDocs, query, where } from 'firebase/firestore'
import app from '../../firebase/config.js'

const db = getFirestore(app)

export default function OrgOverview({ org }) {
  const [stats, setStats] = useState({ users: '-', locations: '-', assets: '-', tickets: '-' })

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const uSnap = await getDocs(query(collection(db, 'users'), where('accountId', '==', org.id), where('active', '==', true)))
        const lSnap = await getDocs(query(collection(db, 'accounts', org.id, 'locations'), where('active', '==', true)))
        const aSnap = await getDocs(query(collection(db, 'accounts', org.id, 'assets'), where('active', '==', true)))
        const tSnap = await getDocs(query(collection(db, 'tickets'), where('accountId', '==', org.id)))
        
        setStats({
          users: uSnap.size,
          locations: lSnap.size,
          assets: aSnap.size,
          tickets: tSnap.size
        })
      } catch (err) {
        console.error('Failed fetching org stats', err)
      }
    }
    fetchStats()
  }, [org.id])

  return (
    <div className="admin-card">
      <h2 style={{ marginTop: 0 }}>Organization Overview</h2>
      
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem', marginBottom: '2rem' }}>
        <div>
          <h3 style={{ color: '#4a5568', fontSize: '0.85rem', textTransform: 'uppercase', marginBottom: '0.5rem' }}>Primary Contact</h3>
          <p style={{ margin: 0, fontWeight: 'bold' }}>{org.primaryContactName || 'Not Set'}</p>
          <p style={{ margin: 0, color: '#718096' }}>{org.primaryContactEmail || 'No Email'}</p>
        </div>
        <div>
          <h3 style={{ color: '#4a5568', fontSize: '0.85rem', textTransform: 'uppercase', marginBottom: '0.5rem' }}>Created At</h3>
          <p style={{ margin: 0 }}>{org.createdAt?.toDate().toLocaleString() || 'Unknown'}</p>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem', borderTop: '1px solid #e2e8f0', paddingTop: '2rem' }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: '2.5rem', fontWeight: 800, color: '#2a4365' }}>{stats.users}</div>
          <div style={{ fontSize: '0.8rem', fontWeight: 'bold', color: '#718096' }}>ACTIVE USERS</div>
        </div>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: '2.5rem', fontWeight: 800, color: '#2a4365' }}>{stats.locations}</div>
          <div style={{ fontSize: '0.8rem', fontWeight: 'bold', color: '#718096' }}>LOCATIONS</div>
        </div>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: '2.5rem', fontWeight: 800, color: '#2a4365' }}>{stats.assets}</div>
          <div style={{ fontSize: '0.8rem', fontWeight: 'bold', color: '#718096' }}>ASSETS</div>
        </div>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: '2.5rem', fontWeight: 800, color: '#f46b45' }}>{stats.tickets}</div>
          <div style={{ fontSize: '0.8rem', fontWeight: 'bold', color: '#718096' }}>TOTAL TICKETS</div>
        </div>
      </div>
    </div>
  )
}
