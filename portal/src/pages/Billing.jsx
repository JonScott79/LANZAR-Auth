import { useState, useEffect } from 'react'
import { getAuth } from 'firebase/auth'
import app from '../firebase/config.js'
import './ListPages.css'
import './Billing.css'

const auth = getAuth(app)
const API_BASE_URL = window.location.hostname === 'localhost'
  ? (import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001')
  : (import.meta.env.VITE_API_BASE_URL && !import.meta.env.VITE_API_BASE_URL.includes('localhost') ? import.meta.env.VITE_API_BASE_URL : 'https://api.tickets.lanzar.me')

const DEFAULT_CATALOG = [
  {
    id: 'homeowner',
    serviceKey: 'it',
    category: 'MANAGED IT',
    name: 'Homeowner Support Plan',
    amount: 4900,
    interval: 'month',
    mode: 'subscription',
    description: '1 hour of direct monthly support, PC & Mac troubleshooting, home Wi-Fi & printer fixes, and priority remote help.',
    directUrl: 'https://buy.stripe.com/14A5kx8RO5BEdcga083oA01'
  },
  {
    id: 'business',
    serviceKey: 'it',
    category: 'MANAGED IT • MOST POPULAR',
    name: 'Small Business Support Plan',
    amount: 25000,
    interval: 'month',
    mode: 'subscription',
    description: '2 hours of direct monthly support, workstation & office network troubleshooting, Microsoft 365 / Google Workspace, and priority scheduling.',
    directUrl: 'https://buy.stripe.com/aFa4gtgkg4xAfkofks3oA04'
  },
  {
    id: 'admin',
    serviceKey: 'it',
    category: 'MANAGED IT • FULL COVERAGE',
    name: 'Full Admin Support Plan',
    amount: 50000,
    interval: 'month',
    mode: 'subscription',
    description: '5 hours of direct monthly support, router/firewall & Windows Server administration, backup status monitoring, and monthly health review.',
    directUrl: 'https://buy.stripe.com/dRmeV7d842psdcgego3oA05'
  }
]

export default function Billing({ customer, user }) {
  const [loading, setLoading] = useState(true)
  const [billingData, setBillingData] = useState({
    activeServices: customer?.services || [],
    subscriptions: [],
    orders: [],
    catalog: DEFAULT_CATALOG
  })
  const [checkoutLoading, setCheckoutLoading] = useState(null)
  const [portalLoading, setPortalLoading] = useState(false)
  const [notice, setNotice] = useState(null)

  // Fetch billing status and catalog
  const fetchBillingStatus = async () => {
    setLoading(true)
    try {
      const token = await auth.currentUser?.getIdToken()
      if (!token) return

      const res = await fetch(`${API_BASE_URL}/api/billing/customer-status`, {
        headers: { 'Authorization': `Bearer ${token}` }
      })
      const data = await res.json()
      if (data.success) {
        setBillingData({
          activeServices: data.activeServices || customer?.services || [],
          subscriptions: data.subscriptions || [],
          orders: data.orders || [],
          catalog: (data.catalog && data.catalog.length > 0) ? data.catalog : DEFAULT_CATALOG
        })
      }
    } catch (err) {
      console.error('[BILLING ERROR] Failed to load status, using default catalog:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    // Check URL parameters for checkout return state
    const params = new URLSearchParams(window.location.search)
    if (params.get('success') === 'true' || params.get('mock_success') === 'true') {
      setNotice({
        type: 'success',
        message: 'Payment completed successfully! Your service entitlement is being updated.'
      })
      // Clean up URL parameter
      window.history.replaceState({}, document.title, window.location.pathname)
    } else if (params.get('canceled') === 'true') {
      setNotice({
        type: 'warning',
        message: 'Checkout was canceled. No charges were made.'
      })
      window.history.replaceState({}, document.title, window.location.pathname)
    }

    fetchBillingStatus()
  }, [])

  // Start Stripe Checkout
  const handleCheckout = async (service) => {
    if (service.directUrl) {
      window.open(service.directUrl, '_blank', 'noopener,noreferrer')
      return
    }

    const serviceId = service.id
    setCheckoutLoading(serviceId)
    setNotice(null)
    try {
      const token = await auth.currentUser?.getIdToken()
      const res = await fetch(`${API_BASE_URL}/api/billing/create-checkout-session`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          serviceId,
          returnUrl: window.location.href.split('?')[0]
        })
      })

      const data = await res.json()
      if (data.success && data.url) {
        window.location.href = data.url
      } else {
        setNotice({ type: 'error', message: data.error || 'Unable to start checkout session.' })
      }
    } catch (err) {
      setNotice({ type: 'error', message: err.message })
    } finally {
      setCheckoutLoading(null)
    }
  }

  // Open Stripe Customer Billing Portal
  const handleOpenBillingPortal = async () => {
    setPortalLoading(true)
    setNotice(null)
    try {
      const token = await auth.currentUser?.getIdToken()
      const res = await fetch(`${API_BASE_URL}/api/billing/create-portal-session`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          returnUrl: window.location.href.split('?')[0]
        })
      })

      const data = await res.json()
      if (data.success && data.url) {
        window.location.href = data.url
      } else {
        setNotice({ type: 'error', message: data.error || 'Unable to open billing portal.' })
      }
    } catch (err) {
      setNotice({ type: 'error', message: err.message })
    } finally {
      setPortalLoading(false)
    }
  }

  return (
    <div className="list-page billing-page">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2>SERVICES &amp; BILLING</h2>
          <p>Commercial service entitlements, subscription management, and payment history.</p>
        </div>
        <button
          className="primary-btn outline billing-portal-btn"
          onClick={handleOpenBillingPortal}
          disabled={portalLoading}
        >
          {portalLoading ? 'CONNECTING...' : 'MANAGE PAYMENT METHODS &rarr;'}
        </button>
      </div>

      {notice && (
        <div className={`billing-notice ${notice.type}`}>
          {notice.message}
        </div>
      )}

      {/* ACTIVE SERVICE ENTITLEMENTS */}
      <section className="billing-section">
        <h3 className="section-title">AUTHORIZED SERVICES</h3>
        <div className="active-services-bar">
          {billingData.activeServices.length === 0 ? (
            <div className="empty-services-note">
              No active paid services currently assigned. Select a service below to initiate access.
            </div>
          ) : (
            billingData.activeServices.map(serviceKey => (
              <div key={serviceKey} className="entitlement-badge active">
                <span className="dot">&#9679;</span>
                <span className="name">{serviceKey.toUpperCase()} SERVICES ACTIVE</span>
              </div>
            ))
          )}
        </div>
      </section>

      {/* SERVICE CATALOG */}
      <section className="billing-section">
        <h3 className="section-title">COMMERCIAL SERVICE CATALOG</h3>
        <p className="section-subtitle">
          Select a verified LANZAR commercial service to begin checkout via secure Stripe processing.
        </p>

        <div className="card-grid">
          {billingData.catalog.map(service => {
            const isSubscribed = billingData.activeServices.includes(service.serviceKey)
            const priceDisplay = `$${(service.amount / 100).toFixed(2)}${service.interval ? ` / ${service.interval}` : ' (One-Time)'}`

            return (
              <div key={service.id} className={`item-card catalog-card ${isSubscribed ? 'subscribed' : ''}`}>
                <div className="item-card-header">
                  <div>
                    <span className="service-category">{service.category}</span>
                    <h3 className="service-title">{service.name}</h3>
                  </div>
                  {isSubscribed && <span className="current-badge">ACTIVE</span>}
                </div>

                <div className="service-pricing">
                  <span className="price">{priceDisplay}</span>
                  <span className="billing-model">{service.mode === 'subscription' ? 'Recurring Subscription' : 'Fixed Scope / Retainer'}</span>
                </div>

                <p className="service-desc">{service.description}</p>

                <div className="card-actions">
                  <button
                    className={`primary-btn ${isSubscribed ? 'outline' : ''}`}
                    onClick={() => handleCheckout(service)}
                    disabled={checkoutLoading === service.id}
                  >
                    {checkoutLoading === service.id
                      ? 'PREPARING...'
                      : isSubscribed
                        ? 'RENEW / MODIFY'
                        : `GET STARTED (${priceDisplay})`}
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      </section>

      {/* INVOICE & ORDER HISTORY */}
      <section className="billing-section">
        <h3 className="section-title">PAYMENT &amp; TRANSACTION HISTORY</h3>
        {billingData.orders.length === 0 ? (
          <div className="empty-history-box">
            No transaction records found for this account.
          </div>
        ) : (
          <table className="orders-table">
            <thead>
              <tr>
                <th>Date</th>
                <th>Service Reference</th>
                <th>Amount</th>
                <th>Status</th>
                <th>Receipt / Reference</th>
              </tr>
            </thead>
            <tbody>
              {billingData.orders.map(order => (
                <tr key={order.id}>
                  <td>{order.paidAt ? new Date(order.paidAt.seconds ? order.paidAt.seconds * 1000 : order.paidAt).toLocaleDateString() : 'Recent'}</td>
                  <td><strong>{order.serviceKey ? order.serviceKey.toUpperCase() : 'LANZAR Service'}</strong></td>
                  <td>${((order.amountTotal || 0) / 100).toFixed(2)} {order.currency?.toUpperCase()}</td>
                  <td><span className="status-pill paid">PAID</span></td>
                  <td className="mono" style={{ fontSize: '0.85rem' }}>{order.id.slice(0, 14)}...</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  )
}
