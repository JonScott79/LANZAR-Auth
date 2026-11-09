// bootstrap.js
// Fail-Closed Startup Bootstrap Validation for LANZAR ID (LID-ARCH-REV-015 §2.4)

const { ENV_CONFIGS } = require('./environments');

class ConfigurationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConfigurationError';
  }
}

function parseServiceAccount(env) {
  if (env.FIREBASE_SERVICE_ACCOUNT_KEY) {
    try {
      return JSON.parse(env.FIREBASE_SERVICE_ACCOUNT_KEY);
    } catch (e) {
      throw new ConfigurationError(`Failed to parse FIREBASE_SERVICE_ACCOUNT_KEY: ${e.message}`);
    }
  }
  if (env.FIREBASE_SERVICE_ACCOUNT_PATH) {
    try {
      const fs = require('fs');
      return JSON.parse(fs.readFileSync(env.FIREBASE_SERVICE_ACCOUNT_PATH, 'utf8'));
    } catch (e) {
      throw new ConfigurationError(`Failed to read FIREBASE_SERVICE_ACCOUNT_PATH: ${e.message}`);
    }
  }
  return null;
}

function bootstrap(env = process.env, options = { exitOnError: false }) {
  function fatal(message) {
    if (options.exitOnError) {
      console.error(`[FATAL BOOTSTRAP ERROR] ${message}`);
      process.exit(1);
    }
    throw new ConfigurationError(message);
  }

  const appEnv = env.APP_ENV;
  if (!appEnv || !ENV_CONFIGS[appEnv]) {
    fatal(`APP_ENV missing or unrecognized: "${appEnv ?? ''}"`);
  }

  const spec = ENV_CONFIGS[appEnv];

  // 1. Exact project ID match
  if (!env.FIREBASE_PROJECT_ID) {
    fatal(`FIREBASE_PROJECT_ID is required for APP_ENV=${appEnv}`);
  }
  if (env.FIREBASE_PROJECT_ID !== spec.projectId) {
    fatal(`APP_ENV=${appEnv} requires FIREBASE_PROJECT_ID=${spec.projectId}, got "${env.FIREBASE_PROJECT_ID}"`);
  }

  // 2. Emulator policy
  const hasAuthEmu = Boolean(env.FIREBASE_AUTH_EMULATOR_HOST);
  const hasFirestoreEmu = Boolean(env.FIRESTORE_EMULATOR_HOST);
  const emuSet = hasAuthEmu || hasFirestoreEmu;

  if (spec.emulators === 'forbidden' && emuSet) {
    fatal(`Emulator host variables set in a live environment (APP_ENV=${appEnv})`);
  }

  // Reject partial emulator configuration across all environments to prevent live/ADC fallback
  if (hasAuthEmu !== hasFirestoreEmu) {
    fatal(`Partial emulator configuration: both FIREBASE_AUTH_EMULATOR_HOST and FIRESTORE_EMULATOR_HOST must be explicitly configured, or neither`);
  }

  function isLoopbackEndpoint(endpoint) {
    if (!endpoint || typeof endpoint !== 'string') return false;
    const parts = endpoint.split(':');
    if (parts.length !== 2) return false;
    const [hostname, port] = parts;
    const portNum = parseInt(port, 10);
    if (isNaN(portNum) || portNum <= 0 || portNum > 65535) return false;
    return hostname === '127.0.0.1' || hostname === 'localhost' || hostname === '::1';
  }

  // Enforce loopback binding for emulator endpoints
  if (hasAuthEmu && !isLoopbackEndpoint(env.FIREBASE_AUTH_EMULATOR_HOST)) {
    fatal(`FIREBASE_AUTH_EMULATOR_HOST must be a local loopback endpoint (127.0.0.1, localhost), got "${env.FIREBASE_AUTH_EMULATOR_HOST}"`);
  }
  if (hasFirestoreEmu && !isLoopbackEndpoint(env.FIRESTORE_EMULATOR_HOST)) {
    fatal(`FIRESTORE_EMULATOR_HOST must be a local loopback endpoint (127.0.0.1, localhost), got "${env.FIRESTORE_EMULATOR_HOST}"`);
  }

  if (spec.emulators === 'required') {
    if (!(hasAuthEmu && hasFirestoreEmu)) {
      fatal(`APP_ENV=${appEnv} requires both FIREBASE_AUTH_EMULATOR_HOST and FIRESTORE_EMULATOR_HOST; refusing to fall back to live resources`);
    }
    if (!spec.projectId.startsWith('demo-')) {
      fatal(`Emulator environments must use a demo- project ID, got "${spec.projectId}"`);
    }
  }

  // 3. Service-account identity verification (live environments only)
  if (spec.saSuffix) {
    const sa = parseServiceAccount(env);
    if (!sa) {
      fatal(`Live environment APP_ENV=${appEnv} requires service-account credentials (FIREBASE_SERVICE_ACCOUNT_KEY or FIREBASE_SERVICE_ACCOUNT_PATH)`);
    }
    if (sa.project_id !== spec.projectId) {
      fatal(`Service-account project_id ("${sa.project_id}") does not match APP_ENV project ("${spec.projectId}")`);
    }
    if (!sa.client_email || !sa.client_email.endsWith(spec.saSuffix)) {
      fatal(`Service-account email ("${sa.client_email || ''}") belongs to another project; must end with "${spec.saSuffix}"`);
    }
    if (env.EXPECTED_SA_EMAIL && sa.client_email !== env.EXPECTED_SA_EMAIL) {
      fatal(`Service-account email ("${sa.client_email}") does not match pinned EXPECTED_SA_EMAIL ("${env.EXPECTED_SA_EMAIL}")`);
    }
  }

  // 4. Session signing secret verification
  if (!env.SESSION_SIGNING_SECRET) {
    fatal('SESSION_SIGNING_SECRET is required');
  }
  if (Buffer.byteLength(env.SESSION_SIGNING_SECRET, 'utf8') < 32) {
    fatal('SESSION_SIGNING_SECRET must be at least 32 bytes (256 bits)');
  }

  // 5. Stripe conditional validation
  const featureStripe = env.FEATURE_STRIPE;
  if (featureStripe === 'enabled') {
    if (!spec.stripeKeyPrefix) {
      fatal(`Stripe cannot be enabled in APP_ENV=${appEnv} (use mocks/disabled in test)`);
    }
    if (!env.STRIPE_SECRET_KEY) {
      fatal('STRIPE_SECRET_KEY is required when FEATURE_STRIPE=enabled');
    }
    if (!env.STRIPE_SECRET_KEY.startsWith(spec.stripeKeyPrefix)) {
      fatal(`STRIPE_SECRET_KEY mode does not match APP_ENV=${appEnv}; expected prefix "${spec.stripeKeyPrefix}"`);
    }
    if (!env.STRIPE_WEBHOOK_SECRET) {
      fatal('STRIPE_WEBHOOK_SECRET is required when FEATURE_STRIPE=enabled');
    }
  } else if (featureStripe !== 'disabled') {
    fatal('FEATURE_STRIPE must be explicitly "enabled" or "disabled"');
  }

  // Return frozen validated configuration
  return Object.freeze({
    ...spec,
    sessionSigningSecret: env.SESSION_SIGNING_SECRET,
    featureStripe: featureStripe === 'enabled',
    stripeSecretKey: env.STRIPE_SECRET_KEY || null,
    stripeWebhookSecret: env.STRIPE_WEBHOOK_SECRET || null,
    nodeEnv: env.NODE_ENV || 'production'
  });
}

module.exports = {
  bootstrap,
  ConfigurationError
};
