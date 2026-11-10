import { useState, useEffect } from 'react'
import { getFirestore, collection, getDocs } from 'firebase/firestore'
import { getAuth } from 'firebase/auth'
import app from '../firebase/config.js'

const db = getFirestore(app)
const auth = getAuth(app)

export default function AdminAnnouncements() {
  const [orgs, setOrgs] = useState([])
  const [subject, setSubject] = useState('')
  const [message, setMessage] = useState('')
  const [targetId, setTargetId] = useState('ALL')

  const [previewMode, setPreviewMode] = useState(false)
  const [sending, setSending] = useState(false)
  const [result, setResult] = useState(null)

  useEffect(() => {
    const fetchOrgs = async () => {
      try {
        const snap = await getDocs(collection(db, 'accounts'))
        const list = []
        snap.forEach(d => list.push({ id: d.id, name: d.data().name }))
        list.sort((a, b) => a.name.localeCompare(b.name))
        setOrgs(list)
      } catch (err) {
        console.error(err)
      }
    }
    fetchOrgs()
  }, [])

  const handlePreview = (e) => {
    e.preventDefault()
    setPreviewMode(true)
  }

  const handleSend = async () => {
    setSending(true)
    setResult(null)
    try {
      const token = await auth.currentUser.getIdToken()
      const res = await fetch(`${import.meta.env.VITE_API_BASE_URL}/api/admin/announcements`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ subject, message, accountId: targetId })
      })
      const data = await res.json()
      if (data.success) {
        setResult({ type: 'success', msg: `Announcement sent successfully to ${data.delivered} recipients (${data.failed} failed).` })
        setSubject('')
        setMessage('')
        setPreviewMode(false)
      } else {
        setResult({ type: 'error', msg: data.error || 'Failed to send announcement.' })
      }
    } catch (err) {
      setResult({ type: 'error', msg: err.message })
    } finally {
      setSending(false)
    }
  }

  return (
    <div>
      <div className="admin-header">
        <h1>Customer Announcements</h1>
      </div>

      <div className="admin-card">
        {result && (
          <div style={{ marginBottom: '2rem', padding: '1rem', background: result.type === 'success' ? '#e6fffa' : '#fed7d7', color: result.type === 'success' ? '#234e52' : '#822727', fontWeight: 'bold' }}>
            {result.msg}
          </div>
        )}

        {!previewMode ? (
          <form onSubmit={handlePreview}>
            <div style={{ marginBottom: '1.5rem' }}>
              <label style={{ display: 'block', fontWeight: 'bold', marginBottom: '0.5rem', color: '#4a5568' }}>Recipients</label>
              <select value={targetId} onChange={e => setTargetId(e.target.value)} style={{ width: '100%', padding: '0.75rem', borderRadius: '4px', border: '1px solid #cbd5e0' }}>
                <option value="ALL">All Active Customers (System-Wide)</option>
                {orgs.map(o => <option key={o.id} value={o.id}>{o.name}</option>)}
              </select>
            </div>

            <div style={{ marginBottom: '1.5rem' }}>
              <label style={{ display: 'block', fontWeight: 'bold', marginBottom: '0.5rem', color: '#4a5568' }}>Subject</label>
              <input type="text" value={subject} onChange={e => setSubject(e.target.value)} required style={{ width: '100%', padding: '0.75rem', borderRadius: '4px', border: '1px solid #cbd5e0' }} placeholder="e.g. Scheduled Network Maintenance" />
            </div>

            <div style={{ marginBottom: '2rem' }}>
              <label style={{ display: 'block', fontWeight: 'bold', marginBottom: '0.5rem', color: '#4a5568' }}>Message</label>
              <textarea value={message} onChange={e => setMessage(e.target.value)} required rows="8" style={{ width: '100%', padding: '0.75rem', borderRadius: '4px', border: '1px solid #cbd5e0', resize: 'vertical' }} placeholder="Enter announcement content here..." />
            </div>

            <button type="submit" className="admin-btn-primary">PREVIEW ANNOUNCEMENT</button>
          </form>
        ) : (
          <div>
            <div style={{ padding: '1.5rem', background: '#f7fafc', border: '1px solid #e2e8f0', borderRadius: '8px', marginBottom: '2rem' }}>
              <h3 style={{ marginTop: 0, color: '#2d3748', borderBottom: '1px solid #cbd5e0', paddingBottom: '0.5rem' }}>Preview</h3>
              <p><strong>To:</strong> {targetId === 'ALL' ? 'ALL CUSTOMERS' : orgs.find(o => o.id === targetId)?.name}</p>
              <p><strong>Subject:</strong> {subject}</p>
              <div style={{ whiteSpace: 'pre-wrap', marginTop: '1.5rem', fontFamily: 'var(--font-body)', lineHeight: 1.6 }}>{message}</div>
            </div>

            <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', background: '#fffaf0', padding: '1.5rem', border: '1px solid #f6e05e', borderRadius: '8px' }}>
              <div style={{ fontSize: '2rem', marginRight: '1rem' }}>⚠️</div>
              <div style={{ flex: 1 }}>
                <h4 style={{ margin: '0 0 0.5rem 0', color: '#b7791f' }}>Confirm Bulk Email</h4>
                <p style={{ margin: 0, color: '#975a16' }}>You are about to send a customer-wide announcement. This cannot be undone.</p>
              </div>
              <div style={{ display: 'flex', gap: '1rem' }}>
                <button className="admin-btn-secondary" onClick={() => setPreviewMode(false)} disabled={sending}>CANCEL</button>
                <button className="admin-btn-primary" onClick={handleSend} disabled={sending} style={{ background: '#e53e3e' }}>
                  {sending ? 'SENDING...' : 'CONFIRM & SEND'}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
