import { useLocation } from 'react-router-dom'
import './Stella.css'

export default function Stella({ user, customer, authError }) {
  const location = useLocation()
  
  let pose = '/images/stella/stella-001.png'
  let message = 'Welcome to your LANZAR account.'

  if (!user || authError) {
    pose = '/images/stella/stella-000.png'
    message = authError ? 'Oh dear! You don\'t have portal access.' : 'Please sign in to manage your LANZAR account.'
  } else if (location.pathname === '/dashboard') {
    pose = '/images/stella/stella-001.png'
    message = `Welcome to your LANZAR account.`
  } else if (location.pathname === '/locations') {
    pose = '/images/stella/stella-002.png'
    message = 'Here are the locations LANZAR is servicing.'
  } else if (location.pathname === '/equipment') {
    pose = '/images/stella/stella-003.png'
    message = 'Let\'s review your registered LANZAR equipment.'
  } else if (location.pathname === '/users') {
    pose = '/images/stella/stella-004.png'
    message = 'These folks are authorized to access LANZAR services.'
  } else if (location.pathname === '/account') {
    pose = '/images/stella/stella-002.png'
    message = 'Here are the details for your organization.'
  }

  return (
    <div className="stella-container">
      <div className="stella-dialogue">
        <img src="/images/decorations/stella-dialog.svg" alt="" className="stella-dialogue-art" aria-hidden="true" />
        <div className="stella-dialogue-content">
          <p className="stella-message">{message}</p>
        </div>
      </div>
      <img src={pose} alt="Stella, LANZAR Support Hostess" className="stella-img" />
    </div>
  )
}
