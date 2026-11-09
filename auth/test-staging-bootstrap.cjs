// test-staging-bootstrap.cjs
// Automated Staging Bootstrap & Startup Safeguard Verification Suite (Phase D)
// Validates strict environment binding, fail-closed isolation, and staging prerequisites

const assert = require('assert');
const { bootstrap, ConfigurationError } = require('./auth-backend/config/bootstrap');

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

function runStagingBootstrapTests() {
  console.log('\n======================================================');
  console.log('LANZAR ID — Staging Bootstrap & Safeguard Verification');
  console.log('Target Environment: staging (lanzar-95ae3-dev)');
  console.log('Timestamp: ' + new Date().toISOString());
  console.log('======================================================\n');

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
    FEATURE_STRIPE: 'disabled'
  };

  // STG-BOOT-1: Clean Staging Bootstrap with Valid Fixtures
  try {
    const config = bootstrap(VALID_STAGING_ENV);
    const pass = 
      config.appEnv === 'staging' &&
      config.projectId === 'lanzar-95ae3-dev' &&
      config.apiBaseUrl === 'https://auth-api-dev.lanzar.me' &&
      config.authHubUrl === 'https://auth-dev.lanzar.me' &&
      config.cookieName === '__Host-lanzar_stg_sess' &&
      config.featureStripe === false;
    recordTest('STG-BOOT-1', 'Valid staging environment boots cleanly with authoritative endpoints and cookie name', pass);
  } catch (e) {
    recordTest('STG-BOOT-1', 'Valid staging environment boots cleanly with authoritative endpoints and cookie name', false, e.message);
  }

  // STG-BOOT-2: Fail-Closed on Prod Service Account Credential
  try {
    let caught = false;
    try {
      bootstrap({
        ...VALID_STAGING_ENV,
        FIREBASE_SERVICE_ACCOUNT_KEY: JSON.stringify({
          project_id: 'lanzar-95ae3',
          client_email: 'lanzar-auth-api@lanzar-95ae3.iam.gserviceaccount.com'
        })
      });
    } catch (e) {
      caught = e.message.includes('does not match APP_ENV project');
    }
    recordTest('STG-BOOT-2', 'Staging startup immediately aborts if production service account key provided', caught);
  } catch (e) {
    recordTest('STG-BOOT-2', 'Staging startup immediately aborts if production service account key provided', false, e.message);
  }

  // STG-BOOT-3: Fail-Closed on Prod Project ID
  try {
    let caught = false;
    try {
      bootstrap({
        ...VALID_STAGING_ENV,
        FIREBASE_PROJECT_ID: 'lanzar-95ae3'
      });
    } catch (e) {
      caught = e.message.includes('requires FIREBASE_PROJECT_ID');
    }
    recordTest('STG-BOOT-3', 'Staging startup immediately aborts if production project ID provided', caught);
  } catch (e) {
    recordTest('STG-BOOT-3', 'Staging startup immediately aborts if production project ID provided', false, e.message);
  }

  // STG-BOOT-4: Fail-Closed on Emulator Host in Staging
  try {
    let caught = false;
    try {
      bootstrap({
        ...VALID_STAGING_ENV,
        FIREBASE_AUTH_EMULATOR_HOST: '127.0.0.1:9099'
      });
    } catch (e) {
      caught = e.message.includes('Emulator host variables set in a live environment');
    }
    recordTest('STG-BOOT-4', 'Staging startup immediately aborts if emulator variables are active', caught);
  } catch (e) {
    recordTest('STG-BOOT-4', 'Staging startup immediately aborts if emulator variables are active', false, e.message);
  }

  // STG-BOOT-5: Fail-Closed on Insufficient Session Secret Length
  try {
    let caught = false;
    try {
      bootstrap({
        ...VALID_STAGING_ENV,
        SESSION_SIGNING_SECRET: 'too_short'
      });
    } catch (e) {
      caught = e.message.includes('SESSION_SIGNING_SECRET must be at least 32 bytes');
    }
    recordTest('STG-BOOT-5', 'Staging startup requires minimum 32-character SESSION_SIGNING_SECRET', caught);
  } catch (e) {
    recordTest('STG-BOOT-5', 'Staging startup requires minimum 32-character SESSION_SIGNING_SECRET', false, e.message);
  }

  // STG-BOOT-6: Stripe Key Prefix Validation (sk_test_ required, sk_live_ rejected in staging)
  try {
    let rejectedLiveKey = false;
    let acceptedTestKey = false;
    try {
      bootstrap({
        ...VALID_STAGING_ENV,
        FEATURE_STRIPE: 'enabled',
        STRIPE_SECRET_KEY: 'sk_live_malicious_prod_key_in_staging',
        STRIPE_WEBHOOK_SECRET: 'whsec_staging_test_secret_123'
      });
    } catch (e) {
      rejectedLiveKey = e.message.includes('expected prefix "sk_test_"');
    }

    try {
      const cfg = bootstrap({
        ...VALID_STAGING_ENV,
        FEATURE_STRIPE: 'enabled',
        STRIPE_SECRET_KEY: 'sk_test_valid_staging_test_key_12345',
        STRIPE_WEBHOOK_SECRET: 'whsec_staging_test_secret_123'
      });
      acceptedTestKey = cfg.featureStripe === true;
    } catch (e) {
      acceptedTestKey = false;
    }

    recordTest('STG-BOOT-6', 'Staging strictly enforces sk_test_ prefix and rejects sk_live_ keys', rejectedLiveKey && acceptedTestKey);
  } catch (e) {
    recordTest('STG-BOOT-6', 'Staging strictly enforces sk_test_ prefix and rejects sk_live_ keys', false, e.message);
  }

  // STG-BOOT-7: Origin Isolation Matrix
  try {
    const config = bootstrap(VALID_STAGING_ENV);
    const originMap = config.originMap;
    const hasDevOrigins = Object.keys(originMap).every(origin => 
      origin.includes('-dev') || origin.includes('localhost') || origin.includes('dev.lanzar.me')
    );
    const hasZeroProdOrigins = !Boolean(originMap['https://auth.lanzar.me']) &&
                               !Boolean(originMap['https://portal.lanzar.me']) &&
                               !Boolean(originMap['https://pythos.lanzar.me']);
    recordTest('STG-BOOT-7', 'Staging origin matrix contains exclusively staging/dev endpoints with zero prod contamination', hasDevOrigins && hasZeroProdOrigins);
  } catch (e) {
    recordTest('STG-BOOT-7', 'Staging origin matrix contains exclusively staging/dev endpoints with zero prod contamination', false, e.message);
  }

  // ----------------------------------------------------
  // Summary
  // ----------------------------------------------------
  console.log('\n======================================================');
  console.log('STAGING BOOTSTRAP TEST SUMMARY');
  console.log(`Total Executed: ${totalTests}`);
  console.log(`Passed:         ${passedTests}`);
  console.log(`Failed:         ${failedTests}`);
  console.log(`Success Rate:   ${((passedTests / totalTests) * 100).toFixed(1)}%`);
  console.log('======================================================\n');

  if (failedTests > 0) {
    process.exit(1);
  }
}

runStagingBootstrapTests();
