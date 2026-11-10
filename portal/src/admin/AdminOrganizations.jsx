import { useState, useEffect } from 'react'
import { getFirestore, collection, getDocs, addDoc, serverTimestamp } from 'firebase/firestore'
import { useNavigate } from 'react-router-dom'
import { getAuth } from 'firebase/auth'
import app from '../firebase/config.js'

const db = getFirestore(app)
const auth = getAuth(app)

export default function AdminOrganizations() {
  const [orgs, setOrgs] = useState([])
  const [loading, setLoading] = useState(true)
  const [showAdd, setShowAdd] = useState(false)
  const [newOrgName, setNewOrgName] = useState('')
  const [newOrgShortName, setNewOrgShortName] = useState('')
  const [newOrgContact, setNewOrgContact] = useState('')
  const [newOrgEmail, setNewOrgEmail] = useState('')
  const [actionMsg, setActionMsg] = useState('')
  const navigate = useNavigate()

  const fetchOrgs = async () => {
    try {
      const snap = await getDocs(collection(db, 'accounts'))
      const list = []
      snap.forEach(doc => {
        list.push({ id: doc.id, ...doc.data() })
      })
      list.sort((a, b) => a.name.localeCompare(b.name))
      setOrgs(list)
    } catch (err) {
      console.error('Failed to fetch orgs', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchOrgs()
  }, [])

  const handleCreateOrg = async (e) => {
    e.preventDefault()
    setActionMsg('Creating organization...')
    try {
      const token = await auth.currentUser.getIdToken()
      const res = await fetch(`${import.meta.env.VITE_API_BASE_URL}/api/accounts`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          name: newOrgName,
          shortName: newOrgShortName,
          primaryContactName: newOrgContact,
          primaryContactEmail: newOrgEmail,
          services: ['it']
        })
      })
      const data = await res.json()
      if (data.success) {
        setActionMsg('Organization created successfully.')
        setNewOrgName('')
        setNewOrgShortName('')
        setNewOrgContact('')
        setNewOrgEmail('')
        setShowAdd(false)
        fetchOrgs()
      } else {
        setActionMsg(data.error || 'Failed to create organization.')
      }
    } catch (err) {
      setActionMsg('Error: ' + err.message)
    }
  }

  return (
    <div>
      <div className="admin-header">
        <h1>Organizations</h1>
        <button className="admin-btn-primary" onClick={() => setShowAdd(!showAdd)}>
          {showAdd ? 'CANCEL' : 'ADD ORGANIZATION'}
        </button>
      </div>

      {actionMsg && <div style={{ marginBottom: '1.5rem', padding: '1rem', background: '#ebf8ff', color: '#2b6cb0', fontWeight: 'bold', borderRadius: '8px' }}>{actionMsg}</div>}

      {showAdd && (
        <div className="admin-card">
          <h2 style={{ marginTop: 0, marginBottom: '1.5rem' }}>Create New Organization</h2>
          <form onSubmit={handleCreateOrg}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem', marginBottom: '1.5rem' }}>
              <div>
                <label style={{ display: 'block', fontWeight: 'bold', marginBottom: '0.5rem', color: '#4a5568' }}>Organization Name *</label>
                <input type="text" value={newOrgName} onChange={e => setNewOrgName(e.target.value)} required style={{ width: '100%', padding: '0.75rem', borderRadius: '4px', border: '1px solid #cbd5e0' }} />
              </div>
              <div>
                <label style={{ display: 'block', fontWeight: 'bold', marginBottom: '0.5rem', color: '#4a5568' }}>Short Name</label>
                <input type="text" value={newOrgShortName} onChange={e => setNewOrgShortName(e.target.value)} style={{ width: '100%', padding: '0.75rem', borderRadius: '4px', border: '1px solid #cbd5e0' }} />
              </div>
              <div>
                <label style={{ display: 'block', fontWeight: 'bold', marginBottom: '0.5rem', color: '#4a5568' }}>Primary Contact Name</label>
                <input type="text" value={newOrgContact} onChange={e => setNewOrgContact(e.target.value)} style={{ width: '100%', padding: '0.75rem', borderRadius: '4px', border: '1px solid #cbd5e0' }} />
              </div>
              <div>
                <label style={{ display: 'block', fontWeight: 'bold', marginBottom: '0.5rem', color: '#4a5568' }}>Primary Contact Email</label>
                <input type="email" value={newOrgEmail} onChange={e => setNewOrgEmail(e.target.value)} style={{ width: '100%', padding: '0.75rem', borderRadius: '4px', border: '1px solid #cbd5e0' }} />
              </div>
            </div>
            <button type="submit" className="admin-btn-primary">CREATE ORGANIZATION</button>
          </form>
        </div>
      )}

      <div className="admin-card" style={{ padding: 0, overflow: 'hidden' }}>
        {loading ? (
          <div style={{ padding: '2rem', textAlign: 'center' }}>Loading organizations...</div>
        ) : orgs.length === 0 ? (
          <div style={{ padding: '2rem', textAlign: 'center' }}>No organizations found.</div>
        ) : (
          <table className="admin-table">
            <thead>
              <tr>
                <th>Organization Name</th>
                <th>Short Name</th>
                <th>Status</th>
                <th>Services</th>
              </tr>
            </thead>
            <tbody>
              {orgs.map(org => (
                <tr key={org.id} onClick={() => navigate(`/admin/orgs/${org.id}`)}>
                  <td style={{ fontWeight: 'bold' }}>{org.name}</td>
                  <td>{org.shortName || '-'}</td>
                  <td>
                    <span className={`status-badge ${org.active !== false ? 'status-active' : 'status-inactive'}`}>
                      {org.active !== false ? 'ACTIVE' : 'INACTIVE'}
                    </span>
                  </td>
                  <td>{org.services?.length || 0}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
