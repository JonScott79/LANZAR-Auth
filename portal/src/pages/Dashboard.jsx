import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { getFirestore, collection, query, where, getDocs } from 'firebase/firestore'
import app from '../firebase/config.js'
import './Dashboard.css'

const db = getFirestore(app)

export default function Dashboard({ customer }) {
  const navigate = useNavigate()
  
  const [counts, setCounts] = useState({
    locations: '-',
    equipment: '-',
    users: '-',
    services: customer.services?.length || 0
  })

  useEffect(() => {
    const fetchCounts = async () => {
      try {
        if (!customer.accountId) return;

        // Fetch Locations
        const locRef = collection(db, 'accounts', customer.accountId, 'locations')
        const locSnap = await getDocs(query(locRef, where('active', '==', true)))
        const locCount = locSnap.size

        // Fetch Assets
        const astRef = collection(db, 'accounts', customer.accountId, 'assets')
        const astSnap = await getDocs(query(astRef, where('active', '==', true)))
        const astCount = astSnap.size

        // Fetch Users (this might be tricky depending on schema, but typically users have accountId)
        const userRef = collection(db, 'users')
        const userSnap = await getDocs(query(userRef, where('accountId', '==', customer.accountId), where('active', '==', true)))
        const userCount = userSnap.size

        setCounts(prev => ({
          ...prev,
          locations: locCount,
          equipment: astCount,
          users: userCount > 0 ? userCount : 1 // at least themselves
        }))
      } catch (err) {
        console.error('Error fetching dashboard counts', err)
      }
    }
    fetchCounts()
  }, [customer])

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <h2>Your LANZAR Account</h2>
        <p>Manage your relationship and view organization details.</p>
      </div>

      <div className="dashboard-modules">
        
        <div className="module-card" onClick={() => navigate('/account')}>
          <div className="module-icon">🏢</div>
          <div className="module-content">
            <h3>ACCOUNT</h3>
            <p>Manage Organization</p>
          </div>
          <div className="module-arrow">&rarr;</div>
        </div>

        <div className="module-card">
          <div className="module-icon">✨</div>
          <div className="module-content">
            <h3>SERVICES</h3>
            <p>{counts.services} Active Service{counts.services !== 1 ? 's' : ''}</p>
          </div>
          <div className="module-arrow">&rarr;</div>
        </div>

        <div className="module-card" onClick={() => navigate('/locations')}>
          <div className="module-icon">📍</div>
          <div className="module-content">
            <h3>LOCATIONS</h3>
            <p>{counts.locations} Location{counts.locations !== 1 ? 's' : ''}</p>
          </div>
          <div className="module-arrow">&rarr;</div>
        </div>

        <div className="module-card" onClick={() => navigate('/equipment')}>
          <div className="module-icon">🖥️</div>
          <div className="module-content">
            <h3>EQUIPMENT</h3>
            <p>{counts.equipment} Asset{counts.equipment !== 1 ? 's' : ''}</p>
          </div>
          <div className="module-arrow">&rarr;</div>
        </div>

        <div className="module-card" onClick={() => navigate('/users')}>
          <div className="module-icon">👤</div>
          <div className="module-content">
            <h3>USERS</h3>
            <p>{counts.users} Authorized User{counts.users !== 1 ? 's' : ''}</p>
          </div>
          <div className="module-arrow">&rarr;</div>
        </div>

      </div>
    </div>
  )
}
