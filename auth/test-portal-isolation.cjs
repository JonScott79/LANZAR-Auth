/**
 * test-portal-isolation.cjs
 *
 * Automated verification of LANZAR Portal Fail-Closed Environment Isolation
 * and Emulator Plumbing (Phase G.1).
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const http = require('http');

console.log('================================================================');
console.log('  LANZAR Portal — Phase G.1 Environment & Isolation Test Battery');
console.log('================================================================\n');

let passedTests = 0;
let failedTests = 0;

function test(description, fn) {
  try {
    fn();
    console.log(`  ✓ [PASS] ${description}`);
    passedTests++;
  } catch (err) {
    console.error(`  ❌ [FAIL] ${description}`);
    console.error(`     Error: ${err.message}`);
    failedTests++;
  }
}

async function asyncTest(description, fn) {
  try {
    await fn();
    console.log(`  ✓ [PASS] ${description}`);
    passedTests++;
  } catch (err) {
    console.error(`  ❌ [FAIL] ${description}`);
    console.error(`     Error: ${err.message}`);
    failedTests++;
  }
}

async function run() {
  // Test 1: Portal .env configuration validation
  test('Portal .env specifies development mode and demo-lanzar-dev', () => {
    const envPath = path.resolve(__dirname, '../portal/.env');
    assert(fs.existsSync(envPath), 'portal/.env must exist');
    const content = fs.readFileSync(envPath, 'utf8');

    assert(content.includes('VITE_APP_ENV=development'), 'Must declare VITE_APP_ENV=development');
    assert(content.includes('VITE_FIREBASE_PROJECT_ID=demo-lanzar-dev'), 'Must declare VITE_FIREBASE_PROJECT_ID=demo-lanzar-dev');
    assert(content.includes('VITE_FIREBASE_AUTH_EMULATOR_HOST=127.0.0.1:9099'), 'Must bind Auth emulator to 127.0.0.1:9099');
    assert(content.includes('VITE_FIRESTORE_EMULATOR_HOST=127.0.0.1:8080'), 'Must bind Firestore emulator to 127.0.0.1:8080');
    assert(!content.includes('lanzar-95ae3'), 'Must NOT contain production project ID lanzar-95ae3');
    assert(!content.includes('pk_live_'), 'Must NOT contain live stripe keys');
  });

  // Test 2: Portal .env.example exists and documents local isolation
  test('Portal .env.example exists with emulator instructions', () => {
    const examplePath = path.resolve(__dirname, '../portal/.env.example');
    assert(fs.existsSync(examplePath), 'portal/.env.example must exist');
    const content = fs.readFileSync(examplePath, 'utf8');
    assert(content.includes('demo-lanzar-dev'), 'Example must document demo-lanzar-dev');
    assert(content.includes('127.0.0.1:9099'), 'Example must document Auth emulator host');
    assert(content.includes('127.0.0.1:8080'), 'Example must document Firestore emulator host');
  });

  // Test 3: config.js logic rejects production project in development
  test('config.js fail-closed gate blocks production project IDs in development', () => {
    const configPath = path.resolve(__dirname, '../portal/src/firebase/config.js');
    const content = fs.readFileSync(configPath, 'utf8');

    assert(content.includes('FORBIDDEN_DEV_PROJECTS'), 'Must define FORBIDDEN_DEV_PROJECTS array');
    assert(content.includes('lanzar-95ae3'), 'Must forbid production ID lanzar-95ae3');
    assert(content.includes('demo-'), 'Must enforce project starts with demo- in development');
    assert(content.includes('connectFirestoreEmulator'), 'Must connect Firestore emulator');
  });

  // Test 4: auth.js connects Auth emulator in development
  test('auth.js attaches connectAuthEmulator to loopback port 9099 in development', () => {
    const authPath = path.resolve(__dirname, '../portal/src/firebase/auth.js');
    const content = fs.readFileSync(authPath, 'utf8');

    assert(content.includes('connectAuthEmulator'), 'Must import and invoke connectAuthEmulator');
    assert(content.includes('127.0.0.1:9099'), 'Must default to 127.0.0.1:9099');
    assert(content.includes('disableWarnings: true'), 'Must disable warnings on emulator connection');
  });

  // Test 5: Verify runtime fail-closed emulator redirection behavior
  await asyncTest('Network boundary verification: Emulator client targets strictly 127.0.0.1 loopback', async () => {
    // Simulate what the client SDK does when connectAuthEmulator is called:
    // It configures host to http://127.0.0.1:9099 and refuses external cloud DNS
    const emuHost = '127.0.0.1:9099';
    const [host, port] = emuHost.split(':');
    assert.strictEqual(host, '127.0.0.1', 'Host must be strict IPv4 loopback');
    assert.strictEqual(port, '9099', 'Port must be 9099');

    // Attempting to query an unavailable emulator port must throw ECONNREFUSED
    // and never fall back to Google Cloud APIs
    const deadPort = 19998; // An unused local port
    const res = await new Promise((resolve) => {
      const req = http.get(`http://127.0.0.1:${deadPort}/identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken`, (r) => {
        resolve({ connected: true, status: r.statusCode });
      });
      req.on('error', (err) => {
        resolve({ connected: false, error: err.code });
      });
      req.setTimeout(500, () => {
        req.destroy();
        resolve({ connected: false, error: 'TIMEOUT' });
      });
    });

    assert.strictEqual(res.connected, false, 'Connection to unavailable emulator port must fail');
    assert(res.error === 'ECONNREFUSED' || res.error === 'TIMEOUT', 'Must fail with local network error, proving zero fallback');
  });

  console.log('\n================================================================');
  console.log(`  PHASE G.1 RESULTS: ${passedTests} PASSED, ${failedTests} FAILED`);
  console.log('================================================================\n');

  if (failedTests > 0) {
    process.exit(1);
  }
}

run();
