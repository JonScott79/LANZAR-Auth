import { useState, useEffect } from 'react'
import { getAuth } from 'firebase/auth'
import app from '../firebase/config.js'

const auth = getAuth(app)
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001'

export default function AdminNewsletter({ admin, user }) {
  const [activeTab, setActiveTab] = useState('compose') // 'compose', 'subscribers', 'history'

  // Subscribers state
  const [subscribers, setSubscribers] = useState([])
  const [subStats, setSubStats] = useState({ total: 0, active: 0, unsubscribed: 0 })
  const [searchFilter, setSearchFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [loadingSubs, setLoadingSubs] = useState(false)

  // Composer state
  const [subject, setSubject] = useState('')
  const [content, setContent] = useState('')
  const [previewMode, setPreviewMode] = useState(false)
  const [sendingTest, setSendingTest] = useState(false)
  const [broadcasting, setBroadcasting] = useState(false)
  const [result, setResult] = useState(null)

  // History state
  const [dispatches, setDispatches] = useState([])
  const [loadingHistory, setLoadingHistory] = useState(false)

  // Fetch subscribers
  const fetchSubscribers = async () => {
    setLoadingSubs(true)
    try {
      const token = await auth.currentUser.getIdToken()
      const res = await fetch(`${API_BASE_URL}/api/admin/newsletter/subscribers`, {
        headers: { 'Authorization': `Bearer ${token}` }
      })
      const data = await res.json()
      if (data.success) {
        setSubscribers(data.subscribers || [])
        setSubStats({
          total: data.total || 0,
          active: data.active || 0,
          unsubscribed: data.unsubscribed || 0
        })
      }
    } catch (err) {
      console.error('[NEWSLETTER] Error fetching subscribers:', err)
    } finally {
      setLoadingSubs(false)
    }
  }

  // Fetch dispatch history
  const fetchHistory = async () => {
    setLoadingHistory(true)
    try {
      const token = await auth.currentUser.getIdToken()
      const res = await fetch(`${API_BASE_URL}/api/admin/newsletter/dispatches`, {
        headers: { 'Authorization': `Bearer ${token}` }
      })
      const data = await res.json()
      if (data.success) {
        setDispatches(data.dispatches || [])
      }
    } catch (err) {
      console.error('[NEWSLETTER] Error fetching history:', err)
    } finally {
      setLoadingHistory(false)
    }
  }

  useEffect(() => {
    fetchSubscribers()
    fetchHistory()
  }, [])

  // Toggle subscriber status (suppression / reactivate)
  const handleToggleStatus = async (subscriber) => {
    const newStatus = subscriber.status === 'active' ? 'unsubscribed' : 'active'
    const confirmMsg = newStatus === 'unsubscribed'
      ? `Suppress ${subscriber.email} from all future broadcasts?`
      : `Reactivate ${subscriber.email}?`
    
    if (!window.confirm(confirmMsg)) return

    try {
      const token = await auth.currentUser.getIdToken()
      const res = await fetch(`${API_BASE_URL}/api/admin/newsletter/subscriber/status`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ id: subscriber.id, status: newStatus })
      })
      const data = await res.json()
      if (data.success) {
        fetchSubscribers()
      } else {
        alert(data.error || 'Failed to update status')
      }
    } catch (err) {
      alert('Error updating status: ' + err.message)
    }
  }

  // Send test email
  const handleSendTest = async () => {
    if (!subject.trim() || !content.trim()) {
      alert('Please fill out Subject and Message content before sending a test.')
      return
    }

    setSendingTest(true)
    setResult(null)
    try {
      const token = await auth.currentUser.getIdToken()
      const res = await fetch(`${API_BASE_URL}/api/admin/newsletter/send-test`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          subject,
          content,
          testEmail: user?.email || 'jon@lanzar.me'
        })
      })
      const data = await res.json()
      if (data.success) {
        setResult({
          type: 'success',
          msg: `Test dispatch delivered successfully to ${data.recipient}.`
        })
      } else {
        setResult({
          type: 'error',
          msg: data.error || 'Test dispatch failed.'
        })
      }
    } catch (err) {
      setResult({ type: 'error', msg: err.message })
    } finally {
      setSendingTest(false)
    }
  }

  // Broadcast campaign to active subscribers
  const handleBroadcast = async () => {
    setBroadcasting(true)
    setResult(null)
    try {
      const token = await auth.currentUser.getIdToken()
      const res = await fetch(`${API_BASE_URL}/api/admin/newsletter/send`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ subject, content })
      })
      const data = await res.json()
      if (data.success) {
        setResult({
          type: 'success',
          msg: `Broadcast dispatched! Accepted: ${data.accepted}, Failed: ${data.failed}.`
        })
        setSubject('')
        setContent('')
        setPreviewMode(false)
        fetchSubscribers()
        fetchHistory()
      } else {
        setResult({
          type: 'error',
          msg: data.error || 'Broadcast failed.'
        })
      }
    } catch (err) {
      setResult({ type: 'error', msg: err.message })
    } finally {
      setBroadcasting(false)
    }
  }

  // Filter subscribers
  const filteredSubscribers = subscribers.filter(sub => {
    const matchesSearch = sub.email.toLowerCase().includes(searchFilter.toLowerCase())
    const matchesStatus = statusFilter === 'ALL' || sub.status === statusFilter
    return matchesSearch && matchesStatus
  })

  return (
    <div>
      <div className="admin-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ margin: 0 }}>LANZAR Dispatch &bull; Mailing List</h1>
          <p style={{ margin: '0.25rem 0 0 0', color: '#718096' }}>
            Compose broadcasts, inspect subscriber registrations, and track delivery.
          </p>
        </div>
        
        {/* Sub-navigation tabs */}
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            onClick={() => setActiveTab('compose')}
            style={{
              padding: '8px 16px',
              borderRadius: '6px',
              border: 'none',
              cursor: 'pointer',
              fontWeight: 'bold',
              background: activeTab === 'compose' ? '#f46b45' : '#e2e8f0',
              color: activeTab === 'compose' ? '#ffffff' : '#4a5568'
            }}
          >
            &#9998; Compose & Send
          </button>
          <button
            onClick={() => { setActiveTab('subscribers'); fetchSubscribers(); }}
            style={{
              padding: '8px 16px',
              borderRadius: '6px',
              border: 'none',
              cursor: 'pointer',
              fontWeight: 'bold',
              background: activeTab === 'subscribers' ? '#f46b45' : '#e2e8f0',
              color: activeTab === 'subscribers' ? '#ffffff' : '#4a5568'
            }}
          >
            &#128101; Subscribers ({subStats.active})
          </button>
          <button
            onClick={() => { setActiveTab('history'); fetchHistory(); }}
            style={{
              padding: '8px 16px',
              borderRadius: '6px',
              border: 'none',
              cursor: 'pointer',
              fontWeight: 'bold',
              background: activeTab === 'history' ? '#f46b45' : '#e2e8f0',
              color: activeTab === 'history' ? '#ffffff' : '#4a5568'
            }}
          >
            &#128220; History ({dispatches.length})
          </button>
        </div>
      </div>

      {result && (
        <div style={{
          margin: '1.5rem 0',
          padding: '1rem 1.5rem',
          borderRadius: '6px',
          background: result.type === 'success' ? '#e6fffa' : '#fed7d7',
          color: result.type === 'success' ? '#234e52' : '#822727',
          fontWeight: 'bold',
          border: `1px solid ${result.type === 'success' ? '#81e6d9' : '#feb2b2'}`
        }}>
          {result.msg}
        </div>
      )}

      {/* ============================================================== */}
      {/* TAB 1: COMPOSE & SEND                                          */}
      {/* ============================================================== */}
      {activeTab === 'compose' && (
        <div className="admin-card">
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            background: '#edf2f7',
            padding: '1rem 1.5rem',
            borderRadius: '6px',
            marginBottom: '1.5rem'
          }}>
            <div>
              <strong>Active Audience:</strong>{' '}
              <span style={{ color: '#2b6cb0', fontWeight: 'bold' }}>
                {subStats.active} active subscribers
              </span>
              {subStats.unsubscribed > 0 && (
                <span style={{ color: '#718096', marginLeft: '0.75rem', fontSize: '0.9rem' }}>
                  ({subStats.unsubscribed} unsubscribed suppressed)
                </span>
              )}
            </div>
            <div>
              <button
                type="button"
                className="admin-btn-secondary"
                onClick={handleSendTest}
                disabled={sendingTest || broadcasting}
                style={{ padding: '6px 14px', fontSize: '0.85rem' }}
              >
                {sendingTest ? 'SENDING TEST...' : `SEND TEST TO ${user?.email || 'ME'}`}
              </button>
            </div>
          </div>

          {!previewMode ? (
            <form onSubmit={(e) => { e.preventDefault(); setPreviewMode(true); }}>
              <div style={{ marginBottom: '1.5rem' }}>
                <label style={{ display: 'block', fontWeight: 'bold', marginBottom: '0.5rem', color: '#4a5568' }}>
                  Subject Line
                </label>
                <input
                  type="text"
                  value={subject}
                  onChange={e => setSubject(e.target.value)}
                  required
                  placeholder="e.g. LANZAR Dispatch #01 — Systems, AI & Architecture"
                  style={{ width: '100%', padding: '0.75rem', borderRadius: '4px', border: '1px solid #cbd5e0', fontSize: '1.1rem' }}
                />
              </div>

              <div style={{ marginBottom: '1rem' }}>
                <label style={{ display: 'block', fontWeight: 'bold', marginBottom: '0.5rem', color: '#4a5568' }}>
                  Transmission Content
                </label>
                <textarea
                  value={content}
                  onChange={e => setContent(e.target.value)}
                  required
                  rows="12"
                  placeholder="Draft your dispatch here. Paragraph breaks are automatically converted to clean email spacing. You may also include HTML tags if desired."
                  style={{
                    width: '100%',
                    padding: '0.75rem',
                    borderRadius: '4px',
                    border: '1px solid #cbd5e0',
                    fontFamily: 'monospace',
                    fontSize: '0.95rem',
                    lineHeight: '1.5'
                  }}
                />
                <span style={{ fontSize: '0.8rem', color: '#718096' }}>
                  Tip: A standardized retro header, brand colors, physical address, and 1-click unsubscribe link are automatically appended.
                </span>
              </div>

              <div style={{ display: 'flex', gap: '1rem', marginTop: '1.5rem' }}>
                <button type="submit" className="admin-btn-primary">
                  PREVIEW DISPATCH
                </button>
              </div>
            </form>
          ) : (
            <div>
              {/* Preview Container */}
              <div style={{
                background: '#0F172A',
                padding: '2rem 1rem',
                borderRadius: '8px',
                marginBottom: '2rem'
              }}>
                <div style={{
                  maxWidth: '560px',
                  margin: '0 auto',
                  background: '#FAF6F0',
                  border: '2px solid #E2B84D',
                  borderRadius: '8px',
                  overflow: 'hidden'
                }}>
                  <div style={{ background: '#102A43', padding: '20px', textAlign: 'center', borderBottom: '3px solid #F46B45' }}>
                    <div style={{ fontSize: '20px', fontWeight: '900', color: '#F5EBDD', letterSpacing: '2px' }}>
                      &#9650; LANZAR DISPATCH
                    </div>
                    <div style={{ fontSize: '11px', color: '#E2B84D', fontWeight: 'bold', marginTop: '4px' }}>
                      Field Notes &bull; Systems &bull; Artificial Intelligence
                    </div>
                  </div>
                  <div style={{ padding: '24px 28px' }}>
                    <h2 style={{ margin: '0 0 16px 0', color: '#102A43', fontSize: '20px' }}>{subject}</h2>
                    <div style={{ whiteSpace: 'pre-wrap', color: '#102A43', lineHeight: 1.6, fontSize: '15px' }}>
                      {content}
                    </div>
                  </div>
                  <div style={{ background: '#F1ECE1', padding: '16px', textAlign: 'center', fontSize: '11px', color: '#556B82', borderTop: '1px solid rgba(16,42,67,0.1)' }}>
                    LANZAR &bull; Worcester, Massachusetts &bull; United States<br/>
                    <span style={{ textDecoration: 'underline' }}>Unsubscribe from LANZAR Dispatch</span>
                  </div>
                </div>
              </div>

              {/* Confirmation Panel */}
              <div style={{
                display: 'flex',
                gap: '1rem',
                alignItems: 'center',
                background: '#fffaf0',
                padding: '1.5rem',
                border: '1px solid #f6e05e',
                borderRadius: '8px'
              }}>
                <div style={{ fontSize: '2rem' }}>⚠️</div>
                <div style={{ flex: 1 }}>
                  <h4 style={{ margin: '0 0 0.5rem 0', color: '#b7791f' }}>Confirm Broadcast Transmission</h4>
                  <p style={{ margin: 0, color: '#975a16' }}>
                    You are about to transmit this dispatch to <strong>{subStats.active} active subscribers</strong>.
                  </p>
                </div>
                <div style={{ display: 'flex', gap: '1rem' }}>
                  <button
                    className="admin-btn-secondary"
                    onClick={() => setPreviewMode(false)}
                    disabled={broadcasting}
                  >
                    BACK TO EDIT
                  </button>
                  <button
                    className="admin-btn-primary"
                    onClick={handleBroadcast}
                    disabled={broadcasting || subStats.active === 0}
                    style={{ background: '#e53e3e' }}
                  >
                    {broadcasting ? 'TRANSMITTING...' : `CONFIRM & BROADCAST (${subStats.active})`}
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ============================================================== */}
      {/* TAB 2: SUBSCRIBERS                                             */}
      {/* ============================================================== */}
      {activeTab === 'subscribers' && (
        <div className="admin-card">
          {/* Summary metrics */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem', marginBottom: '1.5rem' }}>
            <div style={{ background: '#edf2f7', padding: '1rem', borderRadius: '6px', textAlign: 'center' }}>
              <div style={{ fontSize: '0.85rem', color: '#718096', textTransform: 'uppercase', fontWeight: 'bold' }}>Total Signed Up</div>
              <div style={{ fontSize: '1.75rem', fontWeight: 'bold', color: '#2d3748' }}>{subStats.total}</div>
            </div>
            <div style={{ background: '#e6fffa', padding: '1rem', borderRadius: '6px', textAlign: 'center' }}>
              <div style={{ fontSize: '0.85rem', color: '#234e52', textTransform: 'uppercase', fontWeight: 'bold' }}>Active Audience</div>
              <div style={{ fontSize: '1.75rem', fontWeight: 'bold', color: '#319795' }}>{subStats.active}</div>
            </div>
            <div style={{ background: '#fed7d7', padding: '1rem', borderRadius: '6px', textAlign: 'center' }}>
              <div style={{ fontSize: '0.85rem', color: '#822727', textTransform: 'uppercase', fontWeight: 'bold' }}>Unsubscribed / Suppressed</div>
              <div style={{ fontSize: '1.75rem', fontWeight: 'bold', color: '#e53e3e' }}>{subStats.unsubscribed}</div>
            </div>
          </div>

          {/* Filters */}
          <div style={{ display: 'flex', gap: '1rem', marginBottom: '1.5rem' }}>
            <input
              type="text"
              placeholder="Search by email..."
              value={searchFilter}
              onChange={e => setSearchFilter(e.target.value)}
              style={{ flex: 1, padding: '0.6rem 1rem', borderRadius: '4px', border: '1px solid #cbd5e0' }}
            />
            <select
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value)}
              style={{ padding: '0.6rem 1rem', borderRadius: '4px', border: '1px solid #cbd5e0' }}
            >
              <option value="ALL">All Statuses</option>
              <option value="active">Active Only</option>
              <option value="unsubscribed">Unsubscribed Only</option>
            </select>
          </div>

          {/* Table */}
          {loadingSubs ? (
            <div style={{ padding: '2rem', textAlign: 'center', color: '#718096' }}>Loading subscribers...</div>
          ) : filteredSubscribers.length === 0 ? (
            <div style={{ padding: '2rem', textAlign: 'center', color: '#718096' }}>No subscribers found.</div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
              <thead>
                <tr style={{ borderBottom: '2px solid #e2e8f0', color: '#718096', fontSize: '0.85rem', textTransform: 'uppercase' }}>
                  <th style={{ padding: '0.75rem' }}>Email</th>
                  <th style={{ padding: '0.75rem' }}>Status</th>
                  <th style={{ padding: '0.75rem' }}>Subscribed Date</th>
                  <th style={{ padding: '0.75rem' }}>Source</th>
                  <th style={{ padding: '0.75rem', textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredSubscribers.map(sub => (
                  <tr key={sub.id} style={{ borderBottom: '1px solid #edf2f7' }}>
                    <td style={{ padding: '0.75rem', fontWeight: 'bold', color: '#2d3748' }}>{sub.email}</td>
                    <td style={{ padding: '0.75rem' }}>
                      <span style={{
                        padding: '3px 8px',
                        borderRadius: '12px',
                        fontSize: '0.75rem',
                        fontWeight: 'bold',
                        textTransform: 'uppercase',
                        background: sub.status === 'active' ? '#c6f6d5' : '#fed7d7',
                        color: sub.status === 'active' ? '#22543d' : '#822727'
                      }}>
                        {sub.status}
                      </span>
                    </td>
                    <td style={{ padding: '0.75rem', fontSize: '0.9rem', color: '#718096' }}>
                      {sub.subscribedAt ? new Date(sub.subscribedAt).toLocaleDateString() : '—'}
                    </td>
                    <td style={{ padding: '0.75rem', fontSize: '0.85rem', color: '#718096' }}>{sub.source}</td>
                    <td style={{ padding: '0.75rem', textAlign: 'right' }}>
                      <button
                        onClick={() => handleToggleStatus(sub)}
                        style={{
                          background: 'none',
                          border: '1px solid #cbd5e0',
                          padding: '4px 10px',
                          borderRadius: '4px',
                          cursor: 'pointer',
                          fontSize: '0.8rem',
                          color: sub.status === 'active' ? '#c53030' : '#2b6cb0'
                        }}
                      >
                        {sub.status === 'active' ? 'Suppress' : 'Reactivate'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ============================================================== */}
      {/* TAB 3: BROADCAST HISTORY                                       */}
      {/* ============================================================== */}
      {activeTab === 'history' && (
        <div className="admin-card">
          {loadingHistory ? (
            <div style={{ padding: '2rem', textAlign: 'center', color: '#718096' }}>Loading history...</div>
          ) : dispatches.length === 0 ? (
            <div style={{ padding: '2rem', textAlign: 'center', color: '#718096' }}>No broadcasts dispatched yet.</div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
              <thead>
                <tr style={{ borderBottom: '2px solid #e2e8f0', color: '#718096', fontSize: '0.85rem', textTransform: 'uppercase' }}>
                  <th style={{ padding: '0.75rem' }}>Subject</th>
                  <th style={{ padding: '0.75rem' }}>Date Sent</th>
                  <th style={{ padding: '0.75rem' }}>Status</th>
                  <th style={{ padding: '0.75rem' }}>Recipients</th>
                  <th style={{ padding: '0.75rem' }}>Accepted</th>
                  <th style={{ padding: '0.75rem' }}>Failed</th>
                </tr>
              </thead>
              <tbody>
                {dispatches.map(d => (
                  <tr key={d.id} style={{ borderBottom: '1px solid #edf2f7' }}>
                    <td style={{ padding: '0.75rem', fontWeight: 'bold', color: '#2d3748' }}>{d.subject}</td>
                    <td style={{ padding: '0.75rem', fontSize: '0.85rem', color: '#718096' }}>
                      {d.sentAt ? new Date(d.sentAt).toLocaleString() : '—'}
                    </td>
                    <td style={{ padding: '0.75rem' }}>
                      <span style={{
                        padding: '3px 8px',
                        borderRadius: '12px',
                        fontSize: '0.75rem',
                        fontWeight: 'bold',
                        textTransform: 'uppercase',
                        background: d.status === 'completed' ? '#c6f6d5' : (d.status === 'sending' ? '#feebc8' : '#fed7d7'),
                        color: d.status === 'completed' ? '#22543d' : (d.status === 'sending' ? '#744210' : '#822727')
                      }}>
                        {d.status}
                      </span>
                    </td>
                    <td style={{ padding: '0.75rem' }}>{d.recipientCount}</td>
                    <td style={{ padding: '0.75rem', color: '#2b6cb0', fontWeight: 'bold' }}>{d.acceptedCount}</td>
                    <td style={{ padding: '0.75rem', color: d.failedCount > 0 ? '#e53e3e' : '#718096' }}>{d.failedCount}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  )
}
