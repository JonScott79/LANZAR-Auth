import { useState, useEffect, Fragment } from 'react'
import { getFirestore, collection, query, where, getDocs } from 'firebase/firestore'
import { getAuth } from 'firebase/auth'
import app from '../../firebase/config.js'

const db = getFirestore(app)
const auth = getAuth(app)

export default function OrgUsers({ org }) {
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [editUserServices, setEditUserServices] = useState(null)

  const [showAdd, setShowAdd] = useState(false)
  const [newUserName, setNewUserName] = useState('')
  const [newUserEmail, setNewUserEmail] = useState('')
  const [actionMsg, setActionMsg] = useState('')

  const fetchUsers = async () => {
    try {
      const q = query(collection(db, 'users'), where('accountId', '==', org.id))
      const snap = await getDocs(q)
      const list = []
      snap.forEach(d => list.push({ id: d.id, ...d.data() }))
      setUsers(list)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchUsers()
  }, [org.id])

  const handleCreateUser = async (e) => {
    e.preventDefault()
    setActionMsg('Creating user...')
    try {
      const token = await auth.currentUser.getIdToken()
      const res = await fetch(`${import.meta.env.VITE_API_BASE_URL}/api/customers`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          name: newUserName,
          email: newUserEmail,
          accountId: org.id,
          services: org.services || ['it'],
          sendWelcomeEmail: true
        })
      })
      const data = await res.json()
      if (data.success) {
        setActionMsg('User created successfully and invitation sent.')
        setNewUserName('')
        setNewUserEmail('')
        setShowAdd(false)
        fetchUsers()
      } else {
        setActionMsg(data.error || 'Failed to create user.')
      }
    } catch (err) {
      setActionMsg('Error: ' + err.message)
    }
  }

  const handleToggleStatus = async (uid, currentStatus) => {
    try {
      const token = await auth.currentUser.getIdToken()
      const res = await fetch(`${import.meta.env.VITE_API_BASE_URL}/api/customers/${uid}/status`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ active: !currentStatus })
      })
      const data = await res.json()
      if (data.success) {
        fetchUsers()
      } else {
        setActionMsg(`Error updating status: ${data.error || 'Unknown'}`)
      }
    } catch (err) {
      console.error('Failed to update status', err)
      setActionMsg(`Request failed: ${err.message}`)
    }
  }

  return (
    <div className="admin-card" style={{ padding: 0, overflow: 'hidden' }}>
      <div style={{ padding: '1.5rem', borderBottom: '1px solid #e2e8f0', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h2 style={{ margin: 0, fontSize: '1.25rem' }}>Users</h2>
        <button className="admin-btn-primary" onClick={() => setShowAdd(!showAdd)}>
          {showAdd ? 'CANCEL' : 'ADD USER'}
        </button>
      </div>

      {actionMsg && <div style={{ padding: '1rem 1.5rem', background: '#ebf8ff', color: '#2b6cb0', fontWeight: 'bold' }}>{actionMsg}</div>}

      {showAdd && (
        <form onSubmit={handleCreateUser} style={{ padding: '1.5rem', background: '#f7fafc', borderBottom: '1px solid #e2e8f0' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
            <div>
              <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: 'bold', fontSize: '0.9rem' }}>Full Name</label>
              <input type="text" value={newUserName} onChange={e => setNewUserName(e.target.value)} required style={{ width: '100%', padding: '0.5rem', borderRadius: '4px', border: '1px solid #cbd5e0' }} />
            </div>
            <div>
              <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: 'bold', fontSize: '0.9rem' }}>Email Address</label>
              <input type="email" value={newUserEmail} onChange={e => setNewUserEmail(e.target.value)} required style={{ width: '100%', padding: '0.5rem', borderRadius: '4px', border: '1px solid #cbd5e0' }} />
            </div>
          </div>
          <button type="submit" className="admin-btn-primary">CREATE USER & SEND INVITATION</button>
        </form>
      )}

      <table className="admin-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Email</th>
            <th>Role</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {users.map(u => (
            <Fragment key={u.id}>
              <tr>
                <td style={{ fontWeight: 'bold' }}>{u.displayName || 'No Name'}</td>
                <td>{u.email}</td>
                <td>{u.role || 'USER'}</td>
                <td>
                  <span className={`status-badge ${u.active !== false ? 'status-active' : 'status-inactive'}`}>
                    {u.active !== false ? 'ACTIVE' : 'REVOKED'}
                  </span>
                </td>
                <td>
                  <div style={{ display: 'flex', gap: '0.5rem' }}>
                    <button className="admin-btn-secondary" style={{ padding: '0.4rem 0.8rem', fontSize: '0.75rem' }} onClick={() => handleToggleStatus(u.id, u.active !== false)}>
                      {u.active !== false ? 'REVOKE' : 'RE-ENABLE'}
                    </button>
                    <button className="admin-btn-secondary" style={{ padding: '0.4rem 0.8rem', fontSize: '0.75rem' }} onClick={() => setEditUserServices(editUserServices === u.id ? null : u.id)}>
                      SERVICES
                    </button>
                  </div>
                </td>
              </tr>
              {editUserServices === u.id && (
                <tr style={{ background: '#f7fafc' }}>
                  <td colSpan="5" style={{ padding: '1rem 1.5rem', borderBottom: '1px solid #e2e8f0' }}>
                    <div style={{ fontWeight: 'bold', marginBottom: '0.5rem' }}>Authorized Services for {u.displayName || u.email}</div>
                    <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
                      {(org.services || []).map(svcId => {
                        const isAuth = (u.services || []).includes(svcId)
                        return (
                          <label key={svcId} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                            <input type="checkbox" checked={isAuth} onChange={async () => {
                              const newServices = isAuth 
                                ? (u.services || []).filter(s => s !== svcId)
                                : [...(u.services || []), svcId]
                              try {
                                const { updateDoc, doc } = await import('firebase/firestore')
                                await updateDoc(doc(db, 'users', u.id), { services: newServices })
                                fetchUsers()
                              } catch(e) {
                                setActionMsg('Failed to update user services')
                              }
                            }} />
                            <span style={{ fontSize: '0.85rem' }}>{svcId.toUpperCase()}</span>
                          </label>
                        )
                      })}
                    </div>
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
          {users.length === 0 && !loading && (
            <tr><td colSpan="5" style={{ textAlign: 'center', padding: '2rem' }}>No users found in this organization.</td></tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
