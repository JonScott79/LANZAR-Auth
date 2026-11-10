import { useState, useEffect } from 'react'
import { generateRandomString, generateCodeChallenge } from '../pkce.js'
import './Login.css'

export default function Login({ authError: globalAuthError, unauthorized, handleSignOut }) {
  const [loadingMsg, setLoadingMsg] = useState('');

  const initiateAuthHubLogin = async () => {
    setLoadingMsg('Redirecting to LANZAR Identity...');
    const state = generateRandomString();
    const codeVerifier = generateRandomString(64);
    const codeChallenge = await generateCodeChallenge(codeVerifier);

    sessionStorage.setItem('pkce_state', state);
    sessionStorage.setItem('pkce_code_verifier', codeVerifier);

    const redirectUri = window.location.origin;
    
    // Auth Hub frontend URL
    const authHubUrl = 'https://auth.lanzar.me';
    // For local dev, fall back to localhost if we are running locally
    const authUrlBase = window.location.hostname === 'localhost' ? 'http://localhost:4000' : authHubUrl;

    const authUrl = `${authUrlBase}?client_id=portal&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}&code_challenge=${codeChallenge}&code_challenge_method=S256`;
    
    window.location.href = authUrl;
  }

  // If unauthorized, give them the access denied view
  if (unauthorized) {
    return (
      <div className="login-panel">
        <h2 className="login-title">ACCESS DENIED</h2>
        <p className="login-desc">You do not have customer access to this portal.</p>
        {globalAuthError && <p className="error-msg">{globalAuthError}</p>}
        <button className="primary-btn" onClick={handleSignOut}>SIGN OUT</button>
      </div>
    )
  }

  // Otherwise, present the single Auth Hub login button
  return (
    <div className="login-panel" style={{ textAlign: 'center' }}>
      <h2 className="login-title">LANZAR PORTAL</h2>
      <p className="login-desc">Sign in with your centralized LANZAR ID to access your projects and tickets.</p>

      {globalAuthError && <p className="error-msg">{globalAuthError}</p>}

      <div className="form-actions" style={{ justifyContent: 'center', marginTop: '2rem' }}>
        <button 
          type="button" 
          className="primary-btn" 
          onClick={initiateAuthHubLogin} 
          disabled={!!loadingMsg}
        >
          {loadingMsg || 'SIGN IN WITH LANZAR ID'}
        </button>
      </div>
    </div>
  )
}
