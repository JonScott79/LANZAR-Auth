// environments.js
// Authoritative Environment Configuration Matrix for LANZAR ID (LID-ARCH-REV-015 §2.2, §2.3)

const ENV_CONFIGS = {
  production: {
    appEnv: 'production',
    projectId: 'lanzar-95ae3',
    emulators: 'forbidden',
    saSuffix: '@lanzar-95ae3.iam.gserviceaccount.com',
    stripeKeyPrefix: 'sk_live_',
    cookieName: '__Host-lanzar_sess',
    cookieAttributes: 'Path=/; Secure; HttpOnly; SameSite=Lax',
    apiBaseUrl: 'https://auth-api.lanzar.me',
    authHubUrl: 'https://auth.lanzar.me',
    portalUrl: 'https://id.lanzar.me',
    originMap: {
      'https://pythos.lanzar.me': 'pythos',
      'https://tickets.lanzar.me': 'tickets',
      'https://threadline.lanzar.me': 'threadline',
      'https://id.lanzar.me': 'id_portal',
      'https://portal.lanzar.me': 'mission_control',
      'https://lanzar.me': 'marketing_site',
      'https://auth.lanzar.me': 'auth_hub'
    },
    continuationAllowlist: [
      'https://id.lanzar.me/',
      'https://pythos.lanzar.me/',
      'https://tickets.lanzar.me/',
      'https://threadline.lanzar.me/',
      'https://portal.lanzar.me/'
    ]
  },

  staging: {
    appEnv: 'staging',
    projectId: 'lanzar-95ae3-dev',
    emulators: 'forbidden',
    saSuffix: '@lanzar-95ae3-dev.iam.gserviceaccount.com',
    stripeKeyPrefix: 'sk_test_',
    cookieName: '__Host-lanzar_stg_sess',
    cookieAttributes: 'Path=/; Secure; HttpOnly; SameSite=Lax',
    apiBaseUrl: 'https://auth-api-dev.lanzar.me',
    authHubUrl: 'https://auth-dev.lanzar.me',
    portalUrl: 'https://id-dev.lanzar.me',
    originMap: {
      'https://pythos-dev.lanzar.me': 'pythos',
      'https://tickets-dev.lanzar.me': 'tickets',
      'https://threadline-dev.lanzar.me': 'threadline',
      'https://id-dev.lanzar.me': 'id_portal',
      'https://portal-dev.lanzar.me': 'mission_control',
      'https://dev.lanzar.me': 'marketing_site',
      'https://auth-dev.lanzar.me': 'auth_hub'
    },
    continuationAllowlist: [
      'https://id-dev.lanzar.me/',
      'https://pythos-dev.lanzar.me/',
      'https://tickets-dev.lanzar.me/',
      'https://threadline-dev.lanzar.me/',
      'https://portal-dev.lanzar.me/'
    ]
  },

  development: {
    appEnv: 'development',
    projectId: 'demo-lanzar-dev',
    emulators: 'required',
    saSuffix: null,
    stripeKeyPrefix: 'sk_test_',
    cookieName: 'lanzar_dev_sess',
    cookieAttributes: 'Path=/; HttpOnly; SameSite=Lax',
    apiBaseUrl: 'http://localhost:4001',
    authHubUrl: 'http://localhost:4000',
    portalUrl: 'http://localhost:5173',
    originMap: {
      'http://localhost:4000': 'auth_hub',
      'http://127.0.0.1:4000': 'auth_hub',
      'http://localhost:5173': 'mission_control',
      'http://127.0.0.1:5173': 'mission_control',
      'http://localhost:5174': 'tickets',
      'http://localhost:5175': 'threadline',
      'http://localhost:5176': 'ai',
      'http://localhost:3000': 'portal',
      'http://localhost:5178': 'auth_hub_legacy'
    },
    continuationAllowlist: [
      'http://localhost:4000/',
      'http://localhost:5173/',
      'http://localhost:5174/',
      'http://localhost:5175/',
      'http://localhost:5176/',
      'http://localhost:3000/'
    ]
  },

  test: {
    appEnv: 'test',
    projectId: 'demo-lanzar-test',
    emulators: 'required',
    saSuffix: null,
    stripeKeyPrefix: null,
    cookieName: 'lanzar_test_sess',
    cookieAttributes: 'Path=/; HttpOnly; SameSite=Lax',
    apiBaseUrl: 'https://auth-api.test.invalid',
    authHubUrl: 'https://auth.test.invalid',
    portalUrl: 'https://id.test.invalid',
    originMap: {
      'https://pythos.test.invalid': 'pythos',
      'https://tickets.test.invalid': 'tickets',
      'https://threadline.test.invalid': 'threadline',
      'https://id.test.invalid': 'id_portal',
      'https://portal.test.invalid': 'mission_control',
      'https://www.test.invalid': 'marketing_site',
      'https://auth.test.invalid': 'auth_hub'
    },
    continuationAllowlist: [
      'https://id.test.invalid/',
      'https://pythos.test.invalid/',
      'https://tickets.test.invalid/',
      'https://threadline.test.invalid/',
      'https://portal.test.invalid/'
    ]
  }
};

module.exports = { ENV_CONFIGS };
