import { useState, useEffect } from 'react'
import { getAccountAssets, getAccountLocations } from '../firebase/accountResources.js'
import './ListPages.css'

export default function Equipment({ customer }) {
  const [equipment, setEquipment] = useState([])
  const [locations, setLocations] = useState({})
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchData = async () => {
      if (customer.accountId) {
        const [assetsData, locsData] = await Promise.all([
          getAccountAssets(customer.accountId),
          getAccountLocations(customer.accountId)
        ])
        
        const locMap = {}
        locsData.forEach(l => locMap[l.id] = l.name)
        
        setLocations(locMap)
        setEquipment(assetsData)
      }
      setLoading(false)
    }
    fetchData()
  }, [customer])

  return (
    <div className="list-page">
      <div className="page-header">
        <h2>EQUIPMENT</h2>
        <p>Registered assets and hardware.</p>
      </div>

      {loading ? (
        <p className="loading-text">Loading equipment...</p>
      ) : equipment.length === 0 ? (
        <div className="empty-state">
          <p>No equipment found for this organization.</p>
        </div>
      ) : (
        <div className="card-grid">
          {equipment.map(item => (
            <div key={item.id} className="item-card">
              <div className="item-card-header">
                <h3>{item.name}</h3>
                {item.active ? <span className="badge active-badge">ACTIVE</span> : <span className="badge inactive-badge">INACTIVE</span>}
              </div>
              <div className="item-card-body">
                <p><strong>Asset ID:</strong> {item.id}</p>
                <p><strong>Type:</strong> {item.type || 'N/A'}</p>
                <p><strong>Location:</strong> {locations[item.locationId] || item.locationId || 'Unassigned'}</p>
                {item.model && <p><strong>Model:</strong> {item.model}</p>}
                {item.serialNumber && <p><strong>S/N:</strong> {item.serialNumber}</p>}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
