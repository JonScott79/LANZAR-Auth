// test-preprod-failclosed-startup.cjs
// LANZAR ID — Pre-Production Security Hardening Phase 1 Test Suite
// Covers LID-VER-004 (Fail-Closed Startup Validation) & LID-VER-005 (Environment Resolution Hardening)

const assert = require('assert');
const path = require('path');
const http = require('http');
const { spawnSync, spawn } = require('child_process');
const { bootstrap, ConfigurationError } = require('./auth-backend/config/bootstrap');
const { resolveEnvironment, ENV_CONFIGS } = require('./auth-backend/config/environments');
const { getMfaHmacSecret } = require('./auth-backend/mfaService');

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

function recordTest(id, desc, passed, errDetail = null) {
  totalTests++;
  if (passed) {
    passedTests++;
    console.log(`  ✓ [PASS] ${id}: ${desc}`);
  } else {
    failedTests++;
    console.error(`  ✗ [FAIL] ${id}: ${desc}`);
    if (errDetail) console.error(`     Details: ${errDetail}`);
  }
}

const SERVER_PATH = path.resolve(__dirname, 'auth-backend/server.js');

const VALID_STAGING_ENV = {
  APP_ENV: 'staging',
  NODE_ENV: 'production',
  FIREBASE_PROJECT_ID: 'lanzar-95ae3-dev',
  FIREBASE_SERVICE_ACCOUNT_KEY: JSON.stringify({
    project_id: 'lanzar-95ae3-dev',
    client_email: 'lanzar-auth-api@lanzar-95ae3-dev.iam.gserviceaccount.com'
  }),
  EXPECTED_SA_EMAIL: 'lanzar-auth-api@lanzar-95ae3-dev.iam.gserviceaccount.com',
  SESSION_SIGNING_SECRET: 'test_session_signing_secret_at_least_32_bytes_long_123456',
  MFA_HMAC_SECRET: 'staging_mfa_hmac_secret_crypto_safe_random_hex_32_bytes_min',
  FEATURE_STRIPE: 'disabled'
};

const VALID_PROD_ENV = {
  APP_ENV: 'production',
  NODE_ENV: 'production',
  FIREBASE_PROJECT_ID: 'lanzar-95ae3',
  FIREBASE_SERVICE_ACCOUNT_KEY: JSON.stringify({
    project_id: 'lanzar-95ae3',
    client_email: 'lanzar-auth-api@lanzar-95ae3.iam.gserviceaccount.com'
  }),
  EXPECTED_SA_EMAIL: 'lanzar-auth-api@lanzar-95ae3.iam.gserviceaccount.com',
  SESSION_SIGNING_SECRET: 'prod_session_signing_secret_at_least_32_bytes_long_123456',
  MFA_HMAC_SECRET: 'production_mfa_hmac_secret_crypto_safe_random_hex_32_bytes_min',
  FEATURE_STRIPE: 'disabled'
};

async function runPreprodSecuritySuite() {
  console.log('\n======================================================');
  console.log('LANZAR ID — Pre-Production Security Hardening Phase 1');
  console.log('Scope: LID-VER-004 (Startup) & LID-VER-005 (Environment)');
  console.log('Timestamp: ' + new Date().toISOString());
  console.log('======================================================\n');

  // =========================================================================
  // SECTION 1: Environment Resolution Hardening (LID-VER-005)
  // =========================================================================
  console.log('[SECTION 1] LID-VER-005: Environment Resolution Hardening');

  // ENV-01: APP_ENV=production with a valid secret
  try {
    const secret = getMfaHmacSecret({
      APP_ENV: 'production',
      NODE_ENV: 'production',
      MFA_HMAC_SECRET: 'production_mfa_hmac_secret_crypto_safe_random_hex_32_bytes_min'
    });
    recordTest('ENV-01', 'APP_ENV=production with valid 32-byte secret resolves and returns secret', 
      secret === 'production_mfa_hmac_secret_crypto_safe_random_hex_32_bytes_min');
  } catch (e) {
    recordTest('ENV-01', 'APP_ENV=production with valid 32-byte secret resolves and returns secret', false, e.message);
  }

  // ENV-02: APP_ENV=production with no secret
  try {
    let caught = false;
    try {
      getMfaHmacSecret({
        APP_ENV: 'production',
        NODE_ENV: 'production'
      });
    } catch (e) {
      caught = e.message.includes('MFA_HMAC_SECRET must be explicitly configured in APP_ENV=production');
    }
    recordTest('ENV-02', 'APP_ENV=production with no secret fails closed with explicit error', caught);
  } catch (e) {
    recordTest('ENV-02', 'APP_ENV=production with no secret fails closed with explicit error', false, e.message);
  }

  // ENV-03: APP_ENV=production with a weak secret (<32 bytes)
  try {
    let caught = false;
    try {
      getMfaHmacSecret({
        APP_ENV: 'production',
        NODE_ENV: 'production',
        MFA_HMAC_SECRET: 'short_weak_secret'
      });
    } catch (e) {
      caught = e.message.includes('MFA_HMAC_SECRET must be at least 32 bytes in APP_ENV=production');
    }
    recordTest('ENV-03', 'APP_ENV=production with weak secret (<32 bytes) fails closed', caught);
  } catch (e) {
    recordTest('ENV-03', 'APP_ENV=production with weak secret (<32 bytes) fails closed', false, e.message);
  }

  // ENV-04: APP_ENV=staging with no secret
  try {
    let caught = false;
    try {
      getMfaHmacSecret({
        APP_ENV: 'staging',
        NODE_ENV: 'production'
      });
    } catch (e) {
      caught = e.message.includes('MFA_HMAC_SECRET must be explicitly configured in APP_ENV=staging');
    }
    recordTest('ENV-04', 'APP_ENV=staging with no secret fails closed', caught);
  } catch (e) {
    recordTest('ENV-04', 'APP_ENV=staging with no secret fails closed', false, e.message);
  }

  // ENV-05: APP_ENV=staging with a development secret
  try {
    let caught = false;
    try {
      getMfaHmacSecret({
        APP_ENV: 'staging',
        NODE_ENV: 'production',
        MFA_HMAC_SECRET: 'dev_only_local_mfa_signing_secret_for_offline_testing_32b'
      });
    } catch (e) {
      caught = e.message.includes('Known development secret cannot be used for MFA_HMAC_SECRET in APP_ENV=staging');
    }
    recordTest('ENV-05', 'APP_ENV=staging with a development secret fails closed', caught);
  } catch (e) {
    recordTest('ENV-05', 'APP_ENV=staging with a development secret fails closed', false, e.message);
  }

  // ENV-06: NODE_ENV=production with APP_ENV missing (never permits dev defaults)
  try {
    let caughtMissingSecret = false;
    try {
      getMfaHmacSecret({
        NODE_ENV: 'production'
      });
    } catch (e) {
      // Must treat as production and reject missing secret, NEVER falling back to dev secret
      caughtMissingSecret = e.message.includes('MFA_HMAC_SECRET must be explicitly configured in APP_ENV=production');
    }

    let rejectsDevSecret = false;
    try {
      getMfaHmacSecret({
        NODE_ENV: 'production',
        MFA_HMAC_SECRET: 'dev_only_local_mfa_signing_secret_for_offline_testing_32b'
      });
    } catch (e) {
      rejectsDevSecret = e.message.includes('Known development secret cannot be used');
    }

    const acceptsValidSecret = getMfaHmacSecret({
      NODE_ENV: 'production',
      MFA_HMAC_SECRET: 'production_mfa_hmac_secret_crypto_safe_random_hex_32_bytes_min'
    }) === 'production_mfa_hmac_secret_crypto_safe_random_hex_32_bytes_min';

    recordTest('ENV-06', 'NODE_ENV=production with APP_ENV missing enforces production rules and strictly forbids dev defaults',
      caughtMissingSecret && rejectsDevSecret && acceptsValidSecret);
  } catch (e) {
    recordTest('ENV-06', 'NODE_ENV=production with APP_ENV missing enforces production rules and strictly forbids dev defaults', false, e.message);
  }

  // ENV-07: Contradictory environment settings (NODE_ENV=production, APP_ENV=development)
  try {
    let caughtContradiction = false;
    try {
      resolveEnvironment({
        NODE_ENV: 'production',
        APP_ENV: 'development'
      });
    } catch (e) {
      caughtContradiction = e.message.includes('Contradictory environment configuration');
    }

    let mfaCaughtContradiction = false;
    try {
      getMfaHmacSecret({
        NODE_ENV: 'production',
        APP_ENV: 'development'
      });
    } catch (e) {
      mfaCaughtContradiction = e.message.includes('Contradictory environment configuration');
    }

    recordTest('ENV-07', 'Contradictory environment settings fail closed immediately', 
      caughtContradiction && mfaCaughtContradiction);
  } catch (e) {
    recordTest('ENV-07', 'Contradictory environment settings fail closed immediately', false, e.message);
  }

  // ENV-08: Explicit local development with permitted local fallback
  try {
    const fallbackSecret = getMfaHmacSecret({
      APP_ENV: 'development'
    });
    const testFallbackSecret = getMfaHmacSecret({
      APP_ENV: 'test'
    });
    recordTest('ENV-08', 'Explicit local development/test permits offline fallback secret',
      fallbackSecret === 'dev_only_local_mfa_signing_secret_for_offline_testing_32b' &&
      testFallbackSecret === 'dev_only_local_mfa_signing_secret_for_offline_testing_32b');
  } catch (e) {
    recordTest('ENV-08', 'Explicit local development/test permits offline fallback secret', false, e.message);
  }

  // ENV-09: Unverified environment with no APP_ENV and non-production NODE_ENV fails closed
  try {
    let caughtUnverified = false;
    try {
      getMfaHmacSecret({
        NODE_ENV: 'development'
      });
    } catch (e) {
      caughtUnverified = e.message.includes('Environment configuration missing or unrecognized');
    }
    recordTest('ENV-09', 'Unverified environment without explicit APP_ENV fails closed (no accidental dev fallback)', caughtUnverified);
  } catch (e) {
    recordTest('ENV-09', 'Unverified environment without explicit APP_ENV fails closed (no accidental dev fallback)', false, e.message);
  }

  // =========================================================================
  // SECTION 2: Fail-Closed Startup Behavior (LID-VER-004)
  // =========================================================================
  console.log('\n[SECTION 2] LID-VER-004: Fail-Closed Startup Behavior (Process-Level)');

  // BOOT-01: Valid staging configuration passes validation without connecting to staging infrastructure
  try {
    const config = bootstrap(VALID_STAGING_ENV);
    const pass = config.appEnv === 'staging' &&
      config.projectId === 'lanzar-95ae3-dev' &&
      config.apiBaseUrl === 'https://auth-api-dev.lanzar.me';
    recordTest('BOOT-01', 'Valid staging configuration passes bootstrap validation without live network connection', pass);
  } catch (e) {
    recordTest('BOOT-01', 'Valid staging configuration passes bootstrap validation without live network connection', false, e.message);
  }

  // BOOT-02: Missing production MFA secret prevents startup (child process)
  try {
    const envNoSecret = { ...VALID_PROD_ENV };
    delete envNoSecret.MFA_HMAC_SECRET;
    const res = spawnSync(process.execPath, [SERVER_PATH], {
      env: { PATH: process.env.PATH, ...envNoSecret },
      encoding: 'utf8'
    });
    const failedStatus = res.status !== 0;
    const logsError = res.stderr.includes('MFA_HMAC_SECRET is required');
    recordTest('BOOT-02', 'Missing production MFA secret causes immediate process exit with nonzero status',
      failedStatus && logsError);
  } catch (e) {
    recordTest('BOOT-02', 'Missing production MFA secret causes immediate process exit with nonzero status', false, e.message);
  }

  // BOOT-03: Weak production MFA secret prevents startup (child process)
  try {
    const res = spawnSync(process.execPath, [SERVER_PATH], {
      env: { PATH: process.env.PATH, ...VALID_PROD_ENV, MFA_HMAC_SECRET: 'short_secret' },
      encoding: 'utf8'
    });
    const failedStatus = res.status !== 0;
    const logsError = res.stderr.includes('MFA_HMAC_SECRET must be at least 32 bytes');
    recordTest('BOOT-03', 'Weak production MFA secret (<32 bytes) prevents startup with nonzero exit',
      failedStatus && logsError);
  } catch (e) {
    recordTest('BOOT-03', 'Weak production MFA secret (<32 bytes) prevents startup with nonzero exit', false, e.message);
  }

  // BOOT-04: Missing Firebase project ID prevents startup (child process)
  try {
    const envNoProj = { ...VALID_PROD_ENV };
    delete envNoProj.FIREBASE_PROJECT_ID;
    const res = spawnSync(process.execPath, [SERVER_PATH], {
      env: { PATH: process.env.PATH, ...envNoProj },
      encoding: 'utf8'
    });
    const failedStatus = res.status !== 0;
    const logsError = res.stderr.includes('FIREBASE_PROJECT_ID is required');
    recordTest('BOOT-04', 'Missing Firebase project ID prevents startup with nonzero exit',
      failedStatus && logsError);
  } catch (e) {
    recordTest('BOOT-04', 'Missing Firebase project ID prevents startup with nonzero exit', false, e.message);
  }

  // BOOT-05: Missing service account in production prevents startup (child process)
  try {
    const envNoSa = { ...VALID_PROD_ENV };
    delete envNoSa.FIREBASE_SERVICE_ACCOUNT_KEY;
    const res = spawnSync(process.execPath, [SERVER_PATH], {
      env: { PATH: process.env.PATH, ...envNoSa },
      encoding: 'utf8'
    });
    const failedStatus = res.status !== 0;
    const logsError = res.stderr.includes('requires service-account credentials');
    recordTest('BOOT-05', 'Missing service account credentials in production prevents startup with nonzero exit',
      failedStatus && logsError);
  } catch (e) {
    recordTest('BOOT-05', 'Missing service account credentials in production prevents startup with nonzero exit', false, e.message);
  }

  // BOOT-06: Contradictory settings prevent startup before listening (child process)
  try {
    const res = spawnSync(process.execPath, [SERVER_PATH], {
      env: {
        PATH: process.env.PATH,
        NODE_ENV: 'production',
        APP_ENV: 'development',
        FIREBASE_PROJECT_ID: 'demo-lanzar-dev'
      },
      encoding: 'utf8'
    });
    const failedStatus = res.status !== 0;
    const logsError = res.stderr.includes('Contradictory environment configuration');
    recordTest('BOOT-06', 'Contradictory environment settings prevent startup before port is opened',
      failedStatus && logsError);
  } catch (e) {
    recordTest('BOOT-06', 'Contradictory environment settings prevent startup before port is opened', false, e.message);
  }

  // BOOT-07: Bootstrap failure occurs BEFORE listening port is opened
  try {
    // Attempt to start with invalid configuration on custom port 4099
    const testPort = 4099;
    const res = spawnSync(process.execPath, [SERVER_PATH], {
      env: {
        PATH: process.env.PATH,
        PORT: String(testPort),
        APP_ENV: 'production',
        // Omitting required credentials/secrets to guarantee bootstrap failure
      },
      encoding: 'utf8'
    });

    // Check if port 4099 was ever opened or left listening
    const portOpen = await new Promise((resolve) => {
      const req = http.get(`http://127.0.0.1:${testPort}/`, () => resolve(true));
      req.on('error', () => resolve(false));
      setTimeout(() => resolve(false), 500);
    });

    recordTest('BOOT-07', 'Bootstrap failure occurs before listening port is opened; zero network listeners left open',
      res.status !== 0 && !portOpen);
  } catch (e) {
    recordTest('BOOT-07', 'Bootstrap failure occurs before listening port is opened; zero network listeners left open', false, e.message);
  }

  // BOOT-08: Valid local emulator configuration starts successfully (child process)
  try {
    const testPort = 4098;
    const devChild = spawn(process.execPath, [SERVER_PATH], {
      env: {
        PATH: process.env.PATH,
        PORT: String(testPort),
        APP_ENV: 'development',
        NODE_ENV: 'development',
        FIREBASE_PROJECT_ID: 'demo-lanzar-dev',
        FIREBASE_AUTH_EMULATOR_HOST: '127.0.0.1:9099',
        FIRESTORE_EMULATOR_HOST: '127.0.0.1:8080',
        SESSION_SIGNING_SECRET: 'dev_session_signing_secret_min_32_bytes_long_1234'
      },
      stdio: 'pipe'
    });

    let stdoutData = '';
    let stderrData = '';
    devChild.stdout.on('data', (d) => { stdoutData += d.toString(); });
    devChild.stderr.on('data', (d) => { stderrData += d.toString(); });

    // Poll for clean startup message
    let started = false;
    for (let i = 0; i < 20; i++) {
      if (stdoutData.includes(`Operations Center API listening on port ${testPort}`)) {
        started = true;
        break;
      }
      await new Promise((r) => setTimeout(r, 200));
    }

    // Cleanly kill test process
    devChild.kill('SIGTERM');

    recordTest('BOOT-08', 'Valid local emulator configuration starts up cleanly and opens port', started);
  } catch (e) {
    recordTest('BOOT-08', 'Valid local emulator configuration starts up cleanly and opens port', false, e.message);
  }

  // =========================================================================
  // SUMMARY
  // =========================================================================
  console.log('\n======================================================');
  console.log('PRE-PRODUCTION SECURITY HARDENING TEST SUMMARY');
  console.log(`Total Executed: ${totalTests}`);
  console.log(`Passed:         ${passedTests}`);
  console.log(`Failed:         ${failedTests}`);
  console.log(`Success Rate:   ${((passedTests / totalTests) * 100).toFixed(1)}%`);
  console.log('======================================================\n');

  if (failedTests > 0) {
    process.exit(1);
  }
}

runPreprodSecuritySuite().catch((err) => {
  console.error('[FATAL SUITE ERROR]', err);
  process.exit(1);
});
