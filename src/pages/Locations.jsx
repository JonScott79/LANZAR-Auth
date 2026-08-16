import { useState, useEffect } from 'react'
import { getAccountLocations } from '../firebase/accountResources.js'
import './ListPages.css'

export default function Locations({ customer }) {
  const [locations, setLocations] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (customer.accountId) {
      getAccountLocations(customer.accountId).then(data => {
        setLocations(data)
        setLoading(false)
      })
    } else {
      setLoading(false)
    }
  }, [customer])

  return (
    <div className="list-page">
      <div className="page-header">
        <h2>LOCATIONS</h2>
        <p>Facilities currently supported by LANZAR.</p>
      </div>

      {loading ? (
        <p className="loading-text">Loading locations...</p>
      ) : locations.length === 0 ? (
        <div className="empty-state">
          <p>No locations found for this organization.</p>
        </div>
      ) : (
        <div className="card-grid">
          {locations.map(loc => (
            <div key={loc.id} className="item-card">
              <div className="item-card-header">
                <h3>{loc.name}</h3>
                {loc.active ? <span className="badge active-badge">ACTIVE</span> : <span className="badge inactive-badge">INACTIVE</span>}
              </div>
              <div className="item-card-body">
                <p><strong>ID:</strong> {loc.id}</p>
                {loc.address && <p><strong>Address:</strong> {loc.address}</p>}
                {loc.contactName && <p><strong>Contact:</strong> {loc.contactName}</p>}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
