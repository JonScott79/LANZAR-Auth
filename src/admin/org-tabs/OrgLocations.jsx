import { useState, useEffect } from 'react'
import { getFirestore, collection, getDocs, addDoc, updateDoc, doc } from 'firebase/firestore'
import app from '../../firebase/config.js'

const db = getFirestore(app)

export default function OrgLocations({ org }) {
  const [locations, setLocations] = useState([])
  const [showAdd, setShowAdd] = useState(false)
  const [newLocName, setNewLocName] = useState('')

  const fetchLocations = async () => {
    try {
      const snap = await getDocs(collection(db, 'accounts', org.id, 'locations'))
      const list = []
      snap.forEach(d => list.push({ id: d.id, ...d.data() }))
      setLocations(list)
    } catch (err) {
      console.error(err)
    }
  }

  useEffect(() => {
    fetchLocations()
  }, [org.id])

  const handleAdd = async (e) => {
    e.preventDefault()
    try {
      await addDoc(collection(db, 'accounts', org.id, 'locations'), {
        name: newLocName,
        active: true,
      })
      setNewLocName('')
      setShowAdd(false)
      fetchLocations()
    } catch (err) {
      console.error(err)
    }
  }

  const toggleStatus = async (loc) => {
    try {
      await updateDoc(doc(db, 'accounts', org.id, 'locations', loc.id), { active: !loc.active })
      fetchLocations()
    } catch (err) {
      console.error(err)
    }
  }

  return (
    <div className="admin-card" style={{ padding: 0 }}>
      <div style={{ padding: '1.5rem', borderBottom: '1px solid #e2e8f0', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h2 style={{ margin: 0, fontSize: '1.25rem' }}>Locations</h2>
        <button className="admin-btn-primary" onClick={() => setShowAdd(!showAdd)}>
          {showAdd ? 'CANCEL' : 'ADD LOCATION'}
        </button>
      </div>

      {showAdd && (
        <form onSubmit={handleAdd} style={{ padding: '1.5rem', background: '#f7fafc', borderBottom: '1px solid #e2e8f0' }}>
          <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: 'bold' }}>Location Name</label>
          <input type="text" value={newLocName} onChange={e => setNewLocName(e.target.value)} required style={{ width: '100%', maxWidth: '400px', padding: '0.5rem', borderRadius: '4px', border: '1px solid #cbd5e0' }} />
          <div style={{ marginTop: '1rem' }}>
            <button type="submit" className="admin-btn-primary">SAVE LOCATION</button>
          </div>
        </form>
      )}

      <table className="admin-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>ID</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {locations.map(l => (
            <tr key={l.id}>
              <td style={{ fontWeight: 'bold' }}>{l.name}</td>
              <td style={{ fontFamily: 'monospace', color: '#718096' }}>{l.id}</td>
              <td><span className={`status-badge ${l.active ? 'status-active' : 'status-inactive'}`}>{l.active ? 'ACTIVE' : 'INACTIVE'}</span></td>
              <td>
                <button className="admin-btn-secondary" style={{ padding: '0.4rem 0.8rem', fontSize: '0.75rem' }} onClick={() => toggleStatus(l)}>
                  {l.active ? 'DEACTIVATE' : 'ACTIVATE'}
                </button>
              </td>
            </tr>
          ))}
          {locations.length === 0 && <tr><td colSpan="4" style={{ textAlign: 'center', padding: '2rem' }}>No locations found.</td></tr>}
        </tbody>
      </table>
    </div>
  )
}
