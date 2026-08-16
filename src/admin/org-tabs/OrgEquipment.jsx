import { useState, useEffect } from 'react'
import { getFirestore, collection, getDocs, addDoc, updateDoc, doc } from 'firebase/firestore'
import app from '../../firebase/config.js'

const db = getFirestore(app)

export default function OrgEquipment({ org }) {
  const [equipment, setEquipment] = useState([])
  const [locations, setLocations] = useState({})
  const [showAdd, setShowAdd] = useState(false)
  const [newName, setNewName] = useState('')
  const [newLoc, setNewLoc] = useState('')

  const fetchData = async () => {
    try {
      const [astSnap, locSnap] = await Promise.all([
        getDocs(collection(db, 'accounts', org.id, 'assets')),
        getDocs(collection(db, 'accounts', org.id, 'locations'))
      ])
      
      const locMap = {}
      locSnap.forEach(d => locMap[d.id] = d.data().name)
      setLocations(locMap)

      const list = []
      astSnap.forEach(d => list.push({ id: d.id, ...d.data() }))
      setEquipment(list)
    } catch (err) {
      console.error(err)
    }
  }

  useEffect(() => {
    fetchData()
  }, [org.id])

  const handleAdd = async (e) => {
    e.preventDefault()
    try {
      await addDoc(collection(db, 'accounts', org.id, 'assets'), {
        name: newName,
        locationId: newLoc,
        active: true,
      })
      setNewName('')
      setNewLoc('')
      setShowAdd(false)
      fetchData()
    } catch (err) {
      console.error(err)
    }
  }

  const toggleStatus = async (item) => {
    try {
      await updateDoc(doc(db, 'accounts', org.id, 'assets', item.id), { active: !item.active })
      fetchData()
    } catch (err) {
      console.error(err)
    }
  }

  return (
    <div className="admin-card" style={{ padding: 0 }}>
      <div style={{ padding: '1.5rem', borderBottom: '1px solid #e2e8f0', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h2 style={{ margin: 0, fontSize: '1.25rem' }}>Equipment / Assets</h2>
        <button className="admin-btn-primary" onClick={() => setShowAdd(!showAdd)}>
          {showAdd ? 'CANCEL' : 'ADD ASSET'}
        </button>
      </div>

      {showAdd && (
        <form onSubmit={handleAdd} style={{ padding: '1.5rem', background: '#f7fafc', borderBottom: '1px solid #e2e8f0' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
            <div>
              <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: 'bold' }}>Asset Name</label>
              <input type="text" value={newName} onChange={e => setNewName(e.target.value)} required style={{ width: '100%', padding: '0.5rem', borderRadius: '4px', border: '1px solid #cbd5e0' }} />
            </div>
            <div>
              <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: 'bold' }}>Location</label>
              <select value={newLoc} onChange={e => setNewLoc(e.target.value)} style={{ width: '100%', padding: '0.5rem', borderRadius: '4px', border: '1px solid #cbd5e0' }}>
                <option value="">-- Unassigned --</option>
                {Object.entries(locations).map(([id, name]) => (
                  <option key={id} value={id}>{name}</option>
                ))}
              </select>
            </div>
          </div>
          <button type="submit" className="admin-btn-primary">SAVE ASSET</button>
        </form>
      )}

      <table className="admin-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Location</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {equipment.map(e => (
            <tr key={e.id}>
              <td style={{ fontWeight: 'bold' }}>{e.name}</td>
              <td>{locations[e.locationId] || 'Unassigned'}</td>
              <td><span className={`status-badge ${e.active ? 'status-active' : 'status-inactive'}`}>{e.active ? 'ACTIVE' : 'INACTIVE'}</span></td>
              <td>
                <button className="admin-btn-secondary" style={{ padding: '0.4rem 0.8rem', fontSize: '0.75rem' }} onClick={() => toggleStatus(e)}>
                  {e.active ? 'DEACTIVATE' : 'ACTIVATE'}
                </button>
              </td>
            </tr>
          ))}
          {equipment.length === 0 && <tr><td colSpan="4" style={{ textAlign: 'center', padding: '2rem' }}>No equipment found.</td></tr>}
        </tbody>
      </table>
    </div>
  )
}
