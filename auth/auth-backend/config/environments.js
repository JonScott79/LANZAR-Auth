// environments.js
// Authoritative Environment Configuration Matrix for LANZAR ID (LID-ARCH-REV-015 §2.2, §2.3)

const ENV_CONFIGS = {
  production: {
    appEnv: 'production',
    projectId: 'lanzar-95ae3',
    emulators: 'forbidden',
    trustProxy: false,
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
    trustProxy: false,
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
    trustProxy: false,
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
    trustProxy: false,
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

/**
 * Authoritative Environment Resolution (LID-VER-005)
 * Strictly resolves and validates the execution environment across LANZAR ID services.
 *
 * Invariants:
 * 1. An explicit production indicator (NODE_ENV=production or APP_ENV=production) never permits development defaults.
 * 2. An explicit staging environment (NODE_ENV=staging or APP_ENV=staging) never permits development defaults.
 * 3. Contradictory settings (e.g. NODE_ENV=production with APP_ENV=development) fail closed with an error.
 * 4. Missing or unrecognized environments fail closed where security-sensitive behavior is involved.
 * 5. Returns null if environment is missing and non-production/non-staging, preventing unverified fallback.
 *
 * @param {object} env - environment object (defaults to process.env)
 * @returns {string|null} - 'production' | 'staging' | 'development' | 'test' | null
 */
function resolveEnvironment(env = process.env) {
  const rawApp = env && env.APP_ENV !== undefined && env.APP_ENV !== null ? String(env.APP_ENV).trim() : '';
  const rawNode = env && env.NODE_ENV !== undefined && env.NODE_ENV !== null ? String(env.NODE_ENV).trim() : '';

  const appEnv = rawApp.toLowerCase() || null;
  const nodeEnv = rawNode.toLowerCase() || null;

  // 1. Contradictory setting checks (fail closed)
  const isProdNode = nodeEnv === 'production';
  const isStagingNode = nodeEnv === 'staging';
  const isDevNode = nodeEnv === 'development' || nodeEnv === 'test';

  const isProdApp = appEnv === 'production';
  const isStagingApp = appEnv === 'staging';
  const isDevApp = appEnv === 'development' || appEnv === 'test';

  // Production NODE_ENV cannot pair with development/test APP_ENV
  if (isProdNode && isDevApp) {
    throw new Error(`[ENV CONFIG FATAL] Contradictory environment configuration: NODE_ENV is "production" but APP_ENV is "${rawApp}"`);
  }

  // Staging NODE_ENV cannot pair with development/test APP_ENV
  if (isStagingNode && isDevApp) {
    throw new Error(`[ENV CONFIG FATAL] Contradictory environment configuration: NODE_ENV is "staging" but APP_ENV is "${rawApp}"`);
  }

  // Development/test NODE_ENV cannot pair with production/staging APP_ENV
  if (isDevNode && (isProdApp || isStagingApp)) {
    throw new Error(`[ENV CONFIG FATAL] Contradictory environment configuration: NODE_ENV is "${rawNode}" but APP_ENV is "${rawApp}"`);
  }

  // 2. Explicit APP_ENV has highest specificity if valid
  if (appEnv) {
    if (!ENV_CONFIGS[appEnv]) {
      throw new Error(`[ENV CONFIG FATAL] Unrecognized APP_ENV: "${rawApp}"`);
    }
    return appEnv;
  }

  // 3. If APP_ENV is missing, evaluate NODE_ENV
  // Explicit production indicator MUST NOT permit development defaults
  if (isProdNode) {
    return 'production';
  }

  if (isStagingNode) {
    return 'staging';
  }

  // If neither APP_ENV nor NODE_ENV is production/staging,
  // return null to indicate environment is unverified / missing
  return null;
}

module.exports = { ENV_CONFIGS, resolveEnvironment };
