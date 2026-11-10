import { useState, useEffect } from 'react'
import { useParams, useNavigate, Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { getFirestore, doc, getDoc } from 'firebase/firestore'
import app from '../firebase/config.js'

import OrgOverview from './org-tabs/OrgOverview.jsx'
import OrgUsers from './org-tabs/OrgUsers.jsx'
import OrgLocations from './org-tabs/OrgLocations.jsx'
import OrgEquipment from './org-tabs/OrgEquipment.jsx'
import OrgServices from './org-tabs/OrgServices.jsx'

const db = getFirestore(app)

export default function AdminOrgDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const location = useLocation()
  
  const [org, setOrg] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchOrg = async () => {
      try {
        const docRef = doc(db, 'accounts', id)
        const snapshot = await getDoc(docRef)
        if (snapshot.exists()) {
          setOrg({ id: snapshot.id, ...snapshot.data() })
        }
      } catch (err) {
        console.error('Error fetching org', err)
      } finally {
        setLoading(false)
      }
    }
    fetchOrg()
  }, [id])

  if (loading) return <div style={{ padding: '2rem' }}>Loading organization...</div>
  if (!org) return <div style={{ padding: '2rem' }}>Organization not found.</div>

  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'users', label: 'Users' },
    { id: 'locations', label: 'Locations' },
    { id: 'equipment', label: 'Equipment' },
    { id: 'services', label: 'Services' },
  ]

  const currentTab = location.pathname.split('/').pop()

  return (
    <div>
      <div style={{ marginBottom: '1rem' }}>
        <button className="admin-btn-secondary" onClick={() => navigate('/admin/orgs')} style={{ padding: '0.5rem 1rem', fontSize: '0.85rem' }}>
          &larr; Back to Organizations
        </button>
      </div>

      <div className="admin-header" style={{ marginBottom: '1.5rem' }}>
        <div>
          <h1>{org.name}</h1>
          <div style={{ color: '#718096', fontFamily: 'var(--font-code)', marginTop: '0.5rem' }}>
            ID: {org.id} &nbsp;|&nbsp; 
            <span className={`status-badge ${org.active !== false ? 'status-active' : 'status-inactive'}`} style={{ marginLeft: '0.5rem' }}>
              {org.active !== false ? 'ACTIVE' : 'INACTIVE'}
            </span>
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', gap: '1rem', borderBottom: '2px solid #e2e8f0', marginBottom: '2rem' }}>
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => navigate(`/admin/orgs/${org.id}/${tab.id}`)}
            style={{
              background: 'none',
              border: 'none',
              padding: '0.75rem 1.5rem',
              fontFamily: 'var(--font-heading)',
              fontSize: '1rem',
              fontWeight: 600,
              color: currentTab === tab.id ? '#1a2b3c' : '#718096',
              borderBottom: currentTab === tab.id ? '3px solid #f46b45' : '3px solid transparent',
              cursor: 'pointer',
              marginBottom: '-2px'
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <Routes>
        <Route path="/" element={<Navigate to="overview" />} />
        <Route path="overview" element={<OrgOverview org={org} />} />
        <Route path="users" element={<OrgUsers org={org} />} />
        <Route path="locations" element={<OrgLocations org={org} />} />
        <Route path="equipment" element={<OrgEquipment org={org} />} />
        <Route path="services" element={<OrgServices org={org} />} />
      </Routes>
    </div>
  )
}
