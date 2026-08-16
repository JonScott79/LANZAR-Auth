import { useState } from 'react'
import { sendPasswordReset } from '../firebase/auth.js'
import './ListPages.css'

export default function Account({ customer, user }) {
  const [resetSent, setResetSent] = useState(false)
  const [resetError, setResetError] = useState(null)

  const handlePasswordReset = async () => {
    try {
      await sendPasswordReset(user.email)
      setResetSent(true)
      setResetError(null)
    } catch (err) {
      setResetError('Failed to send password reset email.')
    }
  }

  return (
    <div className="list-page">
      <div className="page-header">
        <h2>ACCOUNT</h2>
        <p>Manage your LANZAR relationship.</p>
      </div>

      <div className="account-section">
        <h3>ORGANIZATION DETAILS</h3>
        <div className="info-grid">
          <div className="info-group">
            <span className="info-label">ORGANIZATION NAME</span>
            <span className="info-value">{customer.customerName}</span>
          </div>
          <div className="info-group">
            <span className="info-label">ACCOUNT ID</span>
            <span className="info-value mono">{customer.accountId || customer.id}</span>
          </div>
          <div className="info-group">
            <span className="info-label">ACTIVE SERVICES</span>
            <span className="info-value">{customer.services?.join(', ') || 'None'}</span>
          </div>
        </div>
      </div>

      <div className="account-section">
        <h3>YOUR PROFILE</h3>
        <div className="info-grid">
          <div className="info-group">
            <span className="info-label">DISPLAY NAME</span>
            <span className="info-value">{customer.displayName || 'Not Set'}</span>
          </div>
          <div className="info-group">
            <span className="info-label">EMAIL ADDRESS</span>
            <span className="info-value">{user.email}</span>
          </div>
        </div>
        
        <div className="account-actions">
          <h4>SECURITY</h4>
          <button className="primary-btn outline" onClick={handlePasswordReset}>
            REQUEST PASSWORD RESET
          </button>
          {resetSent && <p className="success-msg mt-1">A password reset link has been sent to your email.</p>}
          {resetError && <p className="error-msg mt-1">{resetError}</p>}
        </div>
      </div>
      
    </div>
  )
}
