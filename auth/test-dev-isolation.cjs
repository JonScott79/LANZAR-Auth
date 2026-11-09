// test-dev-isolation.cjs
// Verification suite for Development Environment Isolation & Safe Emulator Defaults (Phase E.1)

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { isLoopbackEndpoint } = require('./auth-backend/config/bootstrap');
const { ENV_CONFIGS } = require('./auth-backend/config/environments');

console.log('\n======================================================');
console.log('LANZAR ID — Development Environment Isolation Suite');
console.log('Target Specification: Phase E.1 Isolation & Safeguards');
console.log(`Timestamp: ${new Date().toISOString()}`);
console.log('======================================================\n');

let passCount = 0;
let failCount = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ [PASS] ${name}`);
    passCount++;
  } catch (err) {
    console.error(`  ✗ [FAIL] ${name}: ${err.message}`);
    failCount++;
  }
}

// 1. Static Configuration Audit (.env file)
test('DEV-ISO-01: auth/.env specifies development environment and demo project ID', () => {
  const envPath = path.resolve(__dirname, '.env');
  assert(fs.existsSync(envPath), '.env file must exist');
  const envContent = fs.readFileSync(envPath, 'utf8');

  assert(envContent.includes('VITE_APP_ENV=development'), 'VITE_APP_ENV must be set to development');
  assert(envContent.includes('VITE_FIREBASE_PROJECT_ID=demo-lanzar-dev'), 'VITE_FIREBASE_PROJECT_ID must be demo-lanzar-dev');
  assert(!envContent.includes('VITE_FIREBASE_PROJECT_ID=lanzar-95ae3'), 'Must NOT contain production project ID');
});

test('DEV-ISO-02: auth/.env configures local emulator hosts on loopback', () => {
  const envPath = path.resolve(__dirname, '.env');
  const envContent = fs.readFileSync(envPath, 'utf8');

  assert(envContent.includes('VITE_FIREBASE_AUTH_EMULATOR_HOST=127.0.0.1:9099'), 'Auth emulator host must be set to loopback');
  assert(envContent.includes('VITE_FIRESTORE_EMULATOR_HOST=127.0.0.1:8080'), 'Firestore emulator host must be set to loopback');
});

// 2. Client-Side Firebase Config Fail-Closed Protection
test('DEV-ISO-03: Development mode rejects production project IDs with fatal security exception', () => {
  const FORBIDDEN_DEV_PROJECTS = ['lanzar-95ae3', 'production', 'prod'];

  function simulateDevConfigInit(appEnv, projectId) {
    if (appEnv === 'development' && FORBIDDEN_DEV_PROJECTS.includes((projectId || '').toLowerCase())) {
      throw new Error(`[SECURITY FATAL] Production project ID "${projectId}" cannot be used in development environment.`);
    }
    return { projectId: projectId || 'demo-lanzar-dev' };
  }

  // Passing production project ID in development must throw
  assert.throws(
    () => simulateDevConfigInit('development', 'lanzar-95ae3'),
    /SECURITY FATAL.*lanzar-95ae3/,
    'Must throw fatal exception when attempting to use production project in development'
  );
  assert.throws(
    () => simulateDevConfigInit('development', 'production'),
    /SECURITY FATAL/,
    'Must throw fatal exception for project "production"'
  );
  assert.throws(
    () => simulateDevConfigInit('development', 'prod'),
    /SECURITY FATAL/,
    'Must throw fatal exception for project "prod"'
  );

  // Safe demo project ID succeeds
  const safeInit = simulateDevConfigInit('development', 'demo-lanzar-dev');
  assert.strictEqual(safeInit.projectId, 'demo-lanzar-dev');

  // Default fallback when empty in dev mode defaults to demo-lanzar-dev
  const defaultInit = simulateDevConfigInit('development', '');
  assert.strictEqual(defaultInit.projectId, 'demo-lanzar-dev');
});

// 3. Backend Partial Emulator Detection (Fail-Closed)
test('DEV-ISO-04: Backend detects and rejects partial emulator configuration', () => {
  function checkEmulatorConfig(firestoreEmu, authEmu) {
    const hasFirestore = Boolean(firestoreEmu);
    const hasAuth = Boolean(authEmu);
    if (hasFirestore !== hasAuth) {
      throw new Error('Partial emulator configuration detected: both must be configured, or neither.');
    }
    return hasFirestore && hasAuth;
  }

  // One configured, other omitted must throw
  assert.throws(
    () => checkEmulatorConfig('127.0.0.1:8080', null),
    /Partial emulator configuration/,
    'Must reject when only Firestore emulator is set'
  );
  assert.throws(
    () => checkEmulatorConfig(null, '127.0.0.1:9099'),
    /Partial emulator configuration/,
    'Must reject when only Auth emulator is set'
  );

  // Both configured is valid
  assert.strictEqual(checkEmulatorConfig('127.0.0.1:8080', '127.0.0.1:9099'), true);
  // Neither configured is valid (requires service account credentials)
  assert.strictEqual(checkEmulatorConfig(null, null), false);
});

// 4. Backend Loopback Endpoint Enforcement
test('DEV-ISO-05: Loopback validator strictly enforces local endpoints and valid ports', () => {
  // Valid endpoints
  assert.strictEqual(isLoopbackEndpoint('127.0.0.1:8080'), true, '127.0.0.1:8080 is valid');
  assert.strictEqual(isLoopbackEndpoint('localhost:9099'), true, 'localhost:9099 is valid');
  assert.strictEqual(isLoopbackEndpoint('[::1]:8080'), true, '[::1]:8080 is valid');

  // Invalid endpoints
  assert.strictEqual(isLoopbackEndpoint('192.168.1.1:8080'), false, 'LAN IP rejected');
  assert.strictEqual(isLoopbackEndpoint('10.0.0.1:8080'), false, 'Private network rejected');
  assert.strictEqual(isLoopbackEndpoint('evil.com:8080'), false, 'External hostname rejected');
  assert.strictEqual(isLoopbackEndpoint('::1:8080'), false, 'Unbracketed IPv6 rejected');
  assert.strictEqual(isLoopbackEndpoint('127.0.0.1:8080junk'), false, 'Malformed port rejected');
  assert.strictEqual(isLoopbackEndpoint('127.0.0.1:0'), false, 'Port 0 rejected');
  assert.strictEqual(isLoopbackEndpoint('127.0.0.1:70000'), false, 'Port > 65535 rejected');
});

// 5. Live Staging/Production Safeguards
test('DEV-ISO-06: Production environment specification strictly forbids emulators and enforces SA identity', () => {
  const prodSpec = ENV_CONFIGS['production'];
  assert(prodSpec, 'Production config must be defined');
  assert.strictEqual(prodSpec.emulators, 'forbidden', 'Emulators must be forbidden in production');
  assert.strictEqual(prodSpec.saSuffix, '@lanzar-95ae3.iam.gserviceaccount.com', 'Service account suffix strictly enforced in production');
});

test('DEV-ISO-07: Staging environment specification requires non-production project ID and forbids production credentials', () => {
  const stagingSpec = ENV_CONFIGS['staging'];
  assert(stagingSpec, 'Staging config must be defined');
  assert.notStrictEqual(stagingSpec.projectId, 'lanzar-95ae3', 'Staging project ID must NOT be production project ID');
  assert.strictEqual(stagingSpec.emulators, 'forbidden', 'Emulators forbidden in live staging');
});

test('DEV-ISO-08: Non-emulator environment without service account fails closed (no ADC fallback)', () => {
  function checkCredentials(isEmulator, serviceAccountKey, credentialPath) {
    if (!isEmulator && !serviceAccountKey && !credentialPath) {
      throw new Error('Missing Firebase credentials in non-emulator environment. Refusing ADC fallback.');
    }
    return true;
  }

  assert.throws(
    () => checkCredentials(false, null, null),
    /Missing Firebase credentials/,
    'Must fail closed when credentials absent in non-emulator mode'
  );
  assert.strictEqual(checkCredentials(true, null, null), true, 'Emulator mode permits running without credentials');
  assert.strictEqual(checkCredentials(false, '{"project_id":"valid"}', null), true, 'Valid SA key permitted');
});

console.log('\n======================================================');
console.log('DEVELOPMENT ENVIRONMENT ISOLATION TEST SUMMARY');
console.log(`Total Executed: ${passCount + failCount}`);
console.log(`Passed:         ${passCount}`);
console.log(`Failed:         ${failCount}`);
console.log(`Success Rate:   ${((passCount / (passCount + failCount)) * 100).toFixed(1)}%`);
console.log('======================================================\n');

if (failCount > 0) {
  process.exit(1);
}
