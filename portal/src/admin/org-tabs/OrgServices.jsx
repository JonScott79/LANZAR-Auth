import { useState, useEffect } from 'react'
import { getFirestore, updateDoc, doc, collection, getDocs } from 'firebase/firestore'
import app from '../../firebase/config.js'

const db = getFirestore(app)

export default function OrgServices({ org }) {
  const [services, setServices] = useState(org.services || [])
  const [globalServices, setGlobalServices] = useState([])
  const [saving, setSaving] = useState(false)
  const [msg, setMsg] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchGlobal = async () => {
      try {
        const res = await fetch(`${import.meta.env.VITE_API_BASE_URL}/api/services`)
        const data = await res.json()
        if (data.success) {
          const list = data.services.filter(s => s.active)
          list.sort((a, b) => a.name.localeCompare(b.name))
          setGlobalServices(list)
        } else {
          setMsg('Failed to load global services: ' + data.error)
        }
      } catch (e) {
        console.error(e)
        setMsg('Failed to load global services.')
      } finally {
        setLoading(false)
      }
    }
    fetchGlobal()
  }, [])

  const handleToggle = (id) => {
    if (services.includes(id)) {
      setServices(services.filter(s => s !== id))
    } else {
      setServices([...services, id])
    }
  }

  const handleSave = async () => {
    setSaving(true)
    try {
      await updateDoc(doc(db, 'accounts', org.id), { services })
      setMsg('Services updated successfully.')
    } catch (err) {
      console.error(err)
      setMsg('Error saving services.')
    } finally {
      setSaving(false)
    }
  }

  if (loading) return <div className="admin-card"><p>Loading services...</p></div>

  return (
    <div className="admin-card">
      <h2 style={{ marginTop: 0, marginBottom: '1.5rem', fontSize: '1.25rem' }}>Active Services</h2>

      {msg && <div style={{ marginBottom: '1rem', padding: '1rem', background: '#e6fffa', color: '#234e52', fontWeight: 'bold' }}>{msg}</div>}

      <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginBottom: '2rem' }}>
        {globalServices.map(s => (
          <label key={s.id} style={{ display: 'flex', alignItems: 'center', gap: '1rem', padding: '1rem', border: '1px solid #e2e8f0', borderRadius: '4px', cursor: 'pointer', background: services.includes(s.id) ? '#ebf8ff' : 'white' }}>
            <input 
              type="checkbox" 
              checked={services.includes(s.id)}
              onChange={() => handleToggle(s.id)}
              style={{ width: '1.2rem', height: '1.2rem' }}
            />
            <span style={{ fontWeight: 'bold', fontSize: '1.1rem', color: '#2d3748' }}>{s.name}</span>
            <span style={{ marginLeft: 'auto', fontFamily: 'monospace', color: '#718096' }}>{s.id.toUpperCase()}</span>
          </label>
        ))}
      </div>

      <button className="admin-btn-primary" onClick={handleSave} disabled={saving}>
        {saving ? 'SAVING...' : 'SAVE SERVICES'}
      </button>
    </div>
  )
}
