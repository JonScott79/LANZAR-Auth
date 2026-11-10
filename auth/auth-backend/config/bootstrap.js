// bootstrap.js
// Fail-Closed Startup Bootstrap Validation for LANZAR ID (LID-ARCH-REV-015 §2.4, LID-VER-004, LID-VER-005)

const fs = require('fs');
const { ENV_CONFIGS, resolveEnvironment } = require('./environments');

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
  const saPath = env.FIREBASE_SERVICE_ACCOUNT_PATH || env.FIREBASE_CREDENTIAL_PATH;
  if (saPath) {
    try {
      if (!fs.existsSync(saPath)) {
        throw new ConfigurationError(`Specified credential path does not exist: ${saPath}`);
      }
      return JSON.parse(fs.readFileSync(saPath, 'utf8'));
    } catch (e) {
      throw new ConfigurationError(`Failed to read credential from "${saPath}": ${e.message}`);
    }
  }
  return null;
}

/**
 * Validates that an endpoint string is a valid loopback address with an integer port between 1 and 65535.
 * Strictly supports:
 * - IPv4: 127.0.0.1:<port>
 * - Hostname: localhost:<port>
 * - Bracketed IPv6: [::1]:<port>
 *
 * Explicitly rejects unbracketed IPv6 addresses (e.g. ::1:8080), external IP addresses,
 * non-loopback hostnames, malformed ports (e.g. 8080junk, -1, 0, 70000), and missing ports.
 *
 * @param {string} endpoint
 * @returns {boolean}
 */
function isLoopbackEndpoint(endpoint) {
  if (!endpoint || typeof endpoint !== 'string') return false;

  let host;
  let portStr;

  if (endpoint.startsWith('[')) {
    // Bracketed IPv6 format: [::1]:port
    const closingBracket = endpoint.indexOf(']');
    if (closingBracket === -1) return false;
    host = endpoint.slice(1, closingBracket);
    const remainder = endpoint.slice(closingBracket + 1);
    if (!remainder.startsWith(':')) return false;
    portStr = remainder.slice(1);

    // Bracketed IPv6 host must strictly be ::1
    if (host !== '::1') {
      return false;
    }
  } else {
    // Standard host:port format
    // Strictly requires IPv4 loopback (127.0.0.1) or localhost
    // Explicitly rejects unbracketed IPv6 (e.g. ::1:8080)
    const lastColon = endpoint.lastIndexOf(':');
    if (lastColon === -1) return false;
    host = endpoint.slice(0, lastColon);
    portStr = endpoint.slice(lastColon + 1);

    if (host !== '127.0.0.1' && host !== 'localhost') {
      return false;
    }
  }

  // Port validation: strictly digits only, integer between 1 and 65535
  if (!/^\d+$/.test(portStr)) {
    return false;
  }
  const port = Number(portStr);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return false;
  }

  return true;
}

/**
 * Executes comprehensive, fail-closed bootstrap validation for LANZAR ID backend (LID-VER-004, LID-VER-005).
 * Validates environment binding, project IDs, emulators, service account credentials,
 * session signing secrets, and MFA HMAC secrets.
 *
 * @param {object} env - environment variables object (default: process.env)
 * @param {object} options - options { exitOnError: boolean }
 * @returns {object} frozen validated configuration object
 */
function bootstrap(env = process.env, options = { exitOnError: false }) {
  function fatal(message) {
    if (options.exitOnError) {
      console.error(`❌ [FATAL BOOTSTRAP ERROR] ${message}`);
      process.exit(1);
    }
    throw new ConfigurationError(message);
  }

  const hasAuthEmu = Boolean(env.FIREBASE_AUTH_EMULATOR_HOST);
  const hasFirestoreEmu = Boolean(env.FIRESTORE_EMULATOR_HOST);
  const emuSet = hasAuthEmu || hasFirestoreEmu;
  const isEmulator = hasAuthEmu && hasFirestoreEmu;
  const rawProjectId = env.FIREBASE_PROJECT_ID || env.PROJECT_ID;

  // Parse service account if provided (fail early on invalid JSON/file)
  let sa = null;
  try {
    sa = parseServiceAccount(env);
  } catch (saErr) {
    fatal(saErr.message);
  }

  // 1. Resolve environment using authoritative resolution (LID-VER-005)
  let appEnv;
  try {
    appEnv = resolveEnvironment(env);
  } catch (err) {
    fatal(err.message);
  }

  const spec = appEnv ? ENV_CONFIGS[appEnv] : null;

  // If appEnv could not be resolved, enforce pre-flight emulator/credential checks before throwing missing APP_ENV
  if (!appEnv || !spec) {
    if (hasAuthEmu !== hasFirestoreEmu) {
      fatal('Partial emulator configuration detected: both FIREBASE_AUTH_EMULATOR_HOST and FIRESTORE_EMULATOR_HOST must be explicitly configured, or neither');
    }
    if (hasAuthEmu && !isLoopbackEndpoint(env.FIREBASE_AUTH_EMULATOR_HOST)) {
      fatal(`FIREBASE_AUTH_EMULATOR_HOST must be a local loopback endpoint (127.0.0.1, localhost), got "${env.FIREBASE_AUTH_EMULATOR_HOST}"`);
    }
    if (hasFirestoreEmu && !isLoopbackEndpoint(env.FIRESTORE_EMULATOR_HOST)) {
      fatal(`FIRESTORE_EMULATOR_HOST must be a local loopback endpoint (127.0.0.1, localhost), got "${env.FIRESTORE_EMULATOR_HOST}"`);
    }
    if (isEmulator && !rawProjectId) {
      fatal('In emulator mode, FIREBASE_PROJECT_ID is required to prevent accidental default fallback.');
    }
    if (sa && rawProjectId && sa.project_id && sa.project_id !== rawProjectId) {
      fatal(`Project ID mismatch: environment (${rawProjectId}) does not match service account (${sa.project_id})`);
    }
    fatal(`APP_ENV missing or unrecognized: "${env.APP_ENV ?? ''}"`);
  }

  // 2. Exact project ID match against environment specification
  if (!env.FIREBASE_PROJECT_ID) {
    fatal(`FIREBASE_PROJECT_ID is required for APP_ENV=${appEnv}`);
  }
  if (env.FIREBASE_PROJECT_ID !== spec.projectId) {
    fatal(`APP_ENV=${appEnv} requires FIREBASE_PROJECT_ID=${spec.projectId}, got "${env.FIREBASE_PROJECT_ID}"`);
  }

  // 3. Emulator policy per environment spec
  if (spec.emulators === 'forbidden' && emuSet) {
    fatal(`Emulator host variables set in a live environment (APP_ENV=${appEnv})`);
  }

  // Reject partial emulator configuration across all environments to prevent live/ADC fallback
  if (hasAuthEmu !== hasFirestoreEmu) {
    fatal('Partial emulator configuration detected: both FIREBASE_AUTH_EMULATOR_HOST and FIRESTORE_EMULATOR_HOST must be explicitly configured, or neither');
  }

  // Enforce loopback binding for emulator endpoints
  if (hasAuthEmu && !isLoopbackEndpoint(env.FIREBASE_AUTH_EMULATOR_HOST)) {
    fatal(`FIREBASE_AUTH_EMULATOR_HOST must be a local loopback endpoint (127.0.0.1, localhost), got "${env.FIREBASE_AUTH_EMULATOR_HOST}"`);
  }
  if (hasFirestoreEmu && !isLoopbackEndpoint(env.FIRESTORE_EMULATOR_HOST)) {
    fatal(`FIRESTORE_EMULATOR_HOST must be a local loopback endpoint (127.0.0.1, localhost), got "${env.FIRESTORE_EMULATOR_HOST}"`);
  }

  if (spec.emulators === 'required') {
    if (!isEmulator) {
      fatal(`APP_ENV=${appEnv} requires both FIREBASE_AUTH_EMULATOR_HOST and FIRESTORE_EMULATOR_HOST; refusing to fall back to live resources`);
    }
    if (!spec.projectId.startsWith('demo-')) {
      fatal(`Emulator environments must use a demo- project ID, got "${spec.projectId}"`);
    }
  }

  // 4. Service-account identity verification (live environments only)
  if (spec.saSuffix) {
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

  // 5. Cross-check service account vs environment project ID if both present
  if (sa && rawProjectId && sa.project_id && sa.project_id !== rawProjectId) {
    fatal(`Project ID mismatch: environment (${rawProjectId}) does not match service account (${sa.project_id})`);
  }

  // 6. Session signing secret verification
  if (!env.SESSION_SIGNING_SECRET) {
    fatal('SESSION_SIGNING_SECRET is required');
  }
  if (Buffer.byteLength(env.SESSION_SIGNING_SECRET, 'utf8') < 32) {
    fatal('SESSION_SIGNING_SECRET must be at least 32 bytes (256 bits)');
  }

  // 7. MFA HMAC secret verification (LID-SEC-005 & LID-VER-005)
  const KNOWN_DEV_MFA_SECRETS = [
    'lanzar_mfa_signing_key_secure_2026',
    'default_dev_secret',
    'dev_mfa_signing_key_secure_2026',
    'dev_only_local_mfa_signing_secret_for_offline_testing_32b'
  ];

  const mfaSecret = env.MFA_HMAC_SECRET;
  if (appEnv === 'staging' || appEnv === 'production') {
    if (!mfaSecret) {
      fatal(`MFA_HMAC_SECRET is required for APP_ENV=${appEnv}`);
    }
    if (Buffer.byteLength(mfaSecret, 'utf8') < 32) {
      fatal(`MFA_HMAC_SECRET must be at least 32 bytes (256 bits) in APP_ENV=${appEnv}`);
    }
    if (
      KNOWN_DEV_MFA_SECRETS.includes(mfaSecret) ||
      mfaSecret.toLowerCase().includes('dev') ||
      mfaSecret.toLowerCase().includes('default')
    ) {
      fatal(`MFA_HMAC_SECRET cannot use a development or default secret in APP_ENV=${appEnv}`);
    }
  } else {
    // development or test
    if (mfaSecret && Buffer.byteLength(mfaSecret, 'utf8') < 16) {
      fatal(`MFA_HMAC_SECRET, if provided, must be at least 16 bytes in APP_ENV=${appEnv}`);
    }
  }

  // 8. Stripe conditional validation
  // In development and test, default to disabled if omitted; in staging/production, explicit configuration is mandatory
  const featureStripe = env.FEATURE_STRIPE || (appEnv === 'development' || appEnv === 'test' ? 'disabled' : undefined);
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
    nodeEnv: env.NODE_ENV || 'production',
    serviceAccount: sa
  });
}

module.exports = {
  bootstrap,
  ConfigurationError,
  isLoopbackEndpoint,
  resolveEnvironment,
  parseServiceAccount
};
