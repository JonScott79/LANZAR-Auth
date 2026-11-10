import { useState, useEffect } from 'react'
import { getFirestore, collection, query, where, getDocs } from 'firebase/firestore'
import app from '../firebase/config.js'
import './ListPages.css'

const db = getFirestore(app)

export default function Users({ customer }) {
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchUsers = async () => {
      if (customer.accountId) {
        try {
          const userRef = collection(db, 'users')
          const q = query(userRef, where('accountId', '==', customer.accountId))
          const snapshot = await getDocs(q)
          const data = []
          snapshot.forEach(doc => {
            data.push({ id: doc.id, ...doc.data() })
          })
          setUsers(data)
        } catch (err) {
          console.error('Failed to fetch users', err)
        }
      }
      setLoading(false)
    }
    fetchUsers()
  }, [customer])

  return (
    <div className="list-page">
      <div className="page-header">
        <h2>USERS</h2>
        <p>Personnel authorized to access LANZAR services.</p>
      </div>

      {loading ? (
        <p className="loading-text">Loading users...</p>
      ) : users.length === 0 ? (
        <div className="empty-state">
          <p>No authorized users found.</p>
        </div>
      ) : (
        <div className="card-grid">
          {users.map(u => (
            <div key={u.id} className="item-card">
              <div className="item-card-header">
                <h3>{u.displayName || 'Unnamed User'}</h3>
                {u.active !== false ? <span className="badge active-badge">ACTIVE</span> : <span className="badge inactive-badge">INACTIVE</span>}
              </div>
              <div className="item-card-body">
                <p><strong>Email:</strong> {u.email}</p>
                <p><strong>Role:</strong> {u.role || 'USER'}</p>
                <p><strong>User ID:</strong> <span className="mono">{u.id}</span></p>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
