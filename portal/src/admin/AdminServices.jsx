import { useState, useEffect } from 'react'

export default function AdminServices({ user }) {
  const [services, setServices] = useState([])
  const [loading, setLoading] = useState(true)
  const [showAdd, setShowAdd] = useState(false)
  
  const [newId, setNewId] = useState('')
  const [newName, setNewName] = useState('')
  const [newDesc, setNewDesc] = useState('')
  const [newIcon, setNewIcon] = useState('')
  const [newTicketEligible, setNewTicketEligible] = useState(true)
  
  const [actionMsg, setActionMsg] = useState('')
  const [saving, setSaving] = useState(false)

  const fetchServices = async () => {
    try {
      const res = await fetch(`${import.meta.env.VITE_API_BASE_URL}/api/services`)
      const data = await res.json()
      if (data.success) {
        data.services.sort((a, b) => a.name.localeCompare(b.name))
        setServices(data.services)
      } else {
        setActionMsg('Failed to load services: ' + data.error)
      }
    } catch (err) {
      console.error('Failed to fetch services', err)
      setActionMsg('Failed to load services.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchServices()
  }, [])

  const handleSaveService = async (e, id, data) => {
    if (e) e.preventDefault()
    setSaving(true)
    setActionMsg('Saving service...')
    try {
      const { getAuth } = await import('firebase/auth')
      const { default: app } = await import('../firebase/config.js')
      const auth = getAuth(app)
      const token = await auth.currentUser.getIdToken()
      
      const res = await fetch(`${import.meta.env.VITE_API_BASE_URL}/api/services`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ id, data })
      })
      const result = await res.json()
      if (result.success) {
        setActionMsg('Service saved successfully.')
        setShowAdd(false)
        setNewId('')
        setNewName('')
        setNewDesc('')
        setNewIcon('')
        setNewTicketEligible(true)
        fetchServices()
      } else {
        setActionMsg('Error: ' + result.error)
      }
    } catch (err) {
      console.error(err)
      setActionMsg('Error saving service: ' + err.message)
    } finally {
      setSaving(false)
    }
  }

  const toggleStatus = async (svc) => {
    handleSaveService(null, svc.id, { active: !svc.active })
  }
  
  const toggleTicketEligible = async (svc) => {
    handleSaveService(null, svc.id, { ticketEligible: !svc.ticketEligible })
  }

  return (
    <div>
      <div className="admin-header">
        <h1>Global Service Catalog</h1>
        <button className="admin-btn-primary" onClick={() => setShowAdd(!showAdd)}>
          {showAdd ? 'CANCEL' : 'ADD SERVICE'}
        </button>
      </div>

      {actionMsg && <div style={{ marginBottom: '1.5rem', padding: '1rem', background: '#ebf8ff', color: '#2b6cb0', fontWeight: 'bold', borderRadius: '8px' }}>{actionMsg}</div>}

      {showAdd && (
        <div className="admin-card">
          <h2 style={{ marginTop: 0, marginBottom: '1.5rem' }}>Create New Service</h2>
          <form onSubmit={(e) => handleSaveService(e, newId, { 
            name: newName, 
            description: newDesc, 
            icon: newIcon || null,
            ticketEligible: newTicketEligible,
            active: true
          })}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem', marginBottom: '1.5rem' }}>
              <div>
                <label style={{ display: 'block', fontWeight: 'bold', marginBottom: '0.5rem' }}>Service ID (Short Key) *</label>
                <input type="text" value={newId} onChange={e => setNewId(e.target.value)} required style={{ width: '100%', padding: '0.75rem', borderRadius: '4px', border: '1px solid #cbd5e0' }} />
              </div>
              <div>
                <label style={{ display: 'block', fontWeight: 'bold', marginBottom: '0.5rem' }}>Service Name *</label>
                <input type="text" value={newName} onChange={e => setNewName(e.target.value)} required style={{ width: '100%', padding: '0.75rem', borderRadius: '4px', border: '1px solid #cbd5e0' }} />
              </div>
              <div style={{ gridColumn: '1 / -1' }}>
                <label style={{ display: 'block', fontWeight: 'bold', marginBottom: '0.5rem' }}>Description</label>
                <input type="text" value={newDesc} onChange={e => setNewDesc(e.target.value)} style={{ width: '100%', padding: '0.75rem', borderRadius: '4px', border: '1px solid #cbd5e0' }} />
              </div>
              <div>
                <label style={{ display: 'block', fontWeight: 'bold', marginBottom: '0.5rem' }}>Icon Path (optional)</label>
                <input type="text" value={newIcon} onChange={e => setNewIcon(e.target.value)} placeholder="/images/icons/custom.svg" style={{ width: '100%', padding: '0.75rem', borderRadius: '4px', border: '1px solid #cbd5e0' }} />
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <input type="checkbox" checked={newTicketEligible} onChange={e => setNewTicketEligible(e.target.checked)} style={{ width: '1.2rem', height: '1.2rem' }} />
                <label style={{ fontWeight: 'bold' }}>Available in Ticket System</label>
              </div>
            </div>
            <button type="submit" className="admin-btn-primary" disabled={saving}>SAVE SERVICE</button>
          </form>
        </div>
      )}

      <div className="admin-card" style={{ padding: 0, overflow: 'hidden' }}>
        {loading ? (
          <div style={{ padding: '2rem', textAlign: 'center' }}>Loading services...</div>
        ) : services.length === 0 ? (
          <div style={{ padding: '2rem', textAlign: 'center' }}>No services found.</div>
        ) : (
          <table className="admin-table">
            <thead>
              <tr>
                <th>Service Name</th>
                <th>Service ID</th>
                <th>Ticket System</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {services.map(svc => (
                <tr key={svc.id}>
                  <td style={{ fontWeight: 'bold' }}>
                    {svc.name}
                    {svc.description && <div style={{ fontWeight: 'normal', fontSize: '0.85rem', color: '#718096', marginTop: '0.2rem' }}>{svc.description}</div>}
                  </td>
                  <td style={{ fontFamily: 'monospace', color: '#4a5568' }}>{svc.id}</td>
                  <td>
                    <button className="admin-btn-secondary" style={{ padding: '0.4rem 0.8rem', fontSize: '0.75rem' }} onClick={() => toggleTicketEligible(svc)} disabled={saving}>
                      {svc.ticketEligible ? 'ELIGIBLE' : 'EXCLUDED'}
                    </button>
                  </td>
                  <td>
                    <button className="admin-btn-secondary" style={{ padding: '0.4rem 0.8rem', fontSize: '0.75rem', borderColor: svc.active ? '' : '#e53e3e', color: svc.active ? '' : '#e53e3e' }} onClick={() => toggleStatus(svc)} disabled={saving}>
                      {svc.active ? 'ACTIVE' : 'INACTIVE'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
