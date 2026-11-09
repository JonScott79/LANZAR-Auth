// env.js
// Authoritative Frontend Environment Configuration for LANZAR ID

export function getFrontendEnvironment() {
  const hostname = typeof window !== 'undefined' ? window.location.hostname : 'localhost';
  
  if (hostname === 'localhost' || hostname === '127.0.0.1') {
    return 'development';
  }
  if (hostname.includes('-dev') || hostname.includes('staging')) {
    return 'staging';
  }
  return 'production';
}

export function getAuthApiUrl() {
  // Vite environment variable override takes precedence if set
  if (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_AUTH_API_URL) {
    return import.meta.env.VITE_AUTH_API_URL;
  }

  const env = getFrontendEnvironment();
  switch (env) {
    case 'development':
      return 'http://localhost:4001';
    case 'staging':
      return 'https://auth-api-dev.lanzar.me';
    case 'production':
    default:
      return 'https://auth-api.lanzar.me';
  }
}

export function getAuthHubUrl() {
  if (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_AUTH_HUB_URL) {
    return import.meta.env.VITE_AUTH_HUB_URL;
  }

  const env = getFrontendEnvironment();
  switch (env) {
    case 'development':
      return 'http://localhost:4000';
    case 'staging':
      return 'https://auth-dev.lanzar.me';
    case 'production':
    default:
      return 'https://auth.lanzar.me';
  }
}
