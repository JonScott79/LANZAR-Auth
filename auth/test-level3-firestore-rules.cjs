/**
 * test-level3-firestore-rules.cjs
 *
 * LANZAR ID — Level 3 Firestore Security Rules Verification Battery (Step 4.2 Closeout)
 * Target Specification: LID-ARCH-REV-015 §3.3 (Customer Profile Schema & Strict Security Rules)
 *
 * Verifies that client SDK operations (with customer credentials or unauthenticated)
 * are strictly constrained by firestore.rules, completely decoupled from the backend Admin SDK:
 * - Central SSO sessions (/users/{uid}/central_sessions), session slots, and device sessions are server-only.
 * - Authoritative founder records (/users/{uid}/founders) are client-immutable.
 * - Profile updates are strictly constrained to displayName, avatarUrl, and notificationPreferences.
 * - updatedAt is strictly server-controlled (client direct modification denied).
 * - notificationPreferences schema (allowed keys, boolean types only) strictly enforced.
 * - displayName and avatarUrl length and format restrictions (HTTPS-only, no javascript:) strictly enforced.
 * - Server-only security collections (/security_logs, /user_security, /mfa_factors, /phone_otps) are 100% blocked.
 * - Default-deny catches all arbitrary unmapped collections and nested paths.
 * - Cross-user data harvesting and tampering across root and nested collections are blocked.
 * - Unauthenticated anonymous operations are blocked.
 *
 * Lifecycle & Isolation:
 * - Standardized canonical port 8080 (matches firebase.json).
 * - Explicit loopback binding to 127.0.0.1.
 * - Explicit FIRESTORE_EMULATOR_HOST and FIREBASE_AUTH_EMULATOR_HOST endpoints.
 * - Demo-only project ID prefix (demo-lanzar-rules-test) enforcing SDK offline behavior.
 * - Reliable emulator process lifecycle: startup timeout termination, awaited process exit,
 *   PID verification, and cleanup on success, failure, uncaught errors, and termination signals.
 */

const path = require('path');
const fs = require('fs');
const http = require('http');
const { spawn, execSync } = require('child_process');

module.paths.push(path.resolve(__dirname, 'auth-backend/node_modules'));
module.paths.push(path.resolve(__dirname, '../node_modules'));

const {
  initializeTestEnvironment,
  assertFails,
  assertSucceeds
} = require('@firebase/rules-unit-testing');

const PROJECT_ID = 'demo-lanzar-rules-test';
const RULES_PATH = path.resolve(__dirname, '../firestore.rules');
function findEmulatorJar() {
  const cacheDir = path.resolve(process.env.USERPROFILE, '.cache/firebase/emulators');
  if (fs.existsSync(cacheDir)) {
    const files = fs.readdirSync(cacheDir);
    const jar = files.find(f => f.startsWith('cloud-firestore-emulator-') && f.endsWith('.jar'));
    if (jar) return path.join(cacheDir, jar);
  }
  return path.resolve(cacheDir, 'cloud-firestore-emulator-v1.19.8.jar');
}
const EMULATOR_JAR = findEmulatorJar();
const EMULATOR_HOST = '127.0.0.1';
const EMULATOR_PORT = 8080; // Standardized canonical port (matches firebase.json)

let passedTests = 0;
let failedTests = 0;
let emulatorProc = null;
let emulatorClosed = false;
let isReusingActiveEmulator = false;
let testFinishedNormally = false;

function assertCheck(passed, description) {
  if (passed) {
    console.log(`  ✓ [PASS] ${description}`);
    passedTests++;
  } else {
    console.error(`  ❌ [FAIL] ${description}`);
    failedTests++;
  }
}

async function probeEmulatorHealth(host, port, maxAttempts = 10, delayMs = 300) {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const statusCode = await new Promise((resolve, reject) => {
        const req = http.get(`http://${host}:${port}/`, (res) => {
          resolve(res.statusCode);
        });
        req.on('error', reject);
        req.setTimeout(1500, () => {
          req.destroy();
          reject(new Error('Probe timeout'));
        });
      });
      return statusCode;
    } catch (err) {
      if (attempt === maxAttempts) throw err;
      await new Promise(r => setTimeout(r, delayMs));
    }
  }
}

/**
 * Robustly terminates the spawned emulator process, waits for exit,
 * and force-terminates if the process does not terminate within 3 seconds.
 */
async function terminateEmulator() {
  if (isReusingActiveEmulator) {
    return;
  }
  if (!emulatorProc || emulatorClosed) {
    return;
  }
  const pid = emulatorProc.pid;
  console.log(`\n[EMULATOR] Terminating emulator process (PID ${pid})...`);

  try {
    emulatorProc.kill('SIGTERM');
  } catch (_) {}

  // Await process termination
  const exitedGracefully = await new Promise((resolve) => {
    if (emulatorClosed) return resolve(true);
    const timer = setTimeout(() => resolve(false), 3000);
    emulatorProc.once('close', () => {
      clearTimeout(timer);
      emulatorClosed = true;
      resolve(true);
    });
  });

  if (!exitedGracefully) {
    console.warn(`[EMULATOR] Process PID ${pid} did not exit within 3s. Force terminating...`);
    try {
      if (process.platform === 'win32') {
        execSync(`taskkill /F /PID ${pid} /T`, { stdio: 'ignore' });
      } else {
        emulatorProc.kill('SIGKILL');
      }
    } catch (_) {}
  }

  // Final verification that process is gone
  try {
    process.kill(pid, 0); // Throws ESRCH if process does not exist
    console.warn(`[EMULATOR] Warning: PID ${pid} still reporting alive.`);
  } catch (err) {
    if (err.code === 'ESRCH') {
      console.log(`  ✓ Emulator process PID ${pid} confirmed terminated.`);
    }
  }
  emulatorClosed = true;
}

async function runRulesTestSuite() {
  console.log('================================================================');
  console.log('  LANZAR ID — Level 3 Firestore Security Rules Test Battery');
  console.log('  Step 4.2 Closeout & Final Verification');
  console.log(`  Target Project:     ${PROJECT_ID} [OFFLINE LOCAL EMULATOR]`);
  console.log(`  Rules File:         firestore.rules`);
  console.log(`  Emulator Host:      ${EMULATOR_HOST}:${EMULATOR_PORT} [PORT STANDARDIZED]`);
  console.log('  Cloud Access:       STRICTLY ZERO (demo- prefix enforces offline)');
  console.log('================================================================\n');

  // Isolation Guard 1: Verify & strip credentials environment
  if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    console.warn(`[ISOLATION] Stripping GOOGLE_APPLICATION_CREDENTIALS for rules testing.`);
    delete process.env.GOOGLE_APPLICATION_CREDENTIALS;
  }

  // Isolation Guard 2: Require demo- prefix
  if (!PROJECT_ID.startsWith('demo-')) {
    console.error(`[FATAL] Rules test project ID must start with "demo-" to ensure offline mode: ${PROJECT_ID}`);
    process.exit(1);
  }

  // Isolation Guard 3: Explicitly set emulator environment endpoints
  process.env.FIRESTORE_EMULATOR_HOST = `${EMULATOR_HOST}:${EMULATOR_PORT}`;
  process.env.FIREBASE_AUTH_EMULATOR_HOST = `${EMULATOR_HOST}:9099`;

  if (!fs.existsSync(RULES_PATH)) {
    console.error(`[FATAL] Rules file not found at: ${RULES_PATH}`);
    process.exit(1);
  }

  const rulesContent = fs.readFileSync(RULES_PATH, 'utf8');

  // Check if a local Firestore emulator is already active on host:port
  try {
    await probeEmulatorHealth(EMULATOR_HOST, EMULATOR_PORT, 2, 100);
    isReusingActiveEmulator = true;
    console.log(`[EMULATOR] Active Firestore emulator detected on ${EMULATOR_HOST}:${EMULATOR_PORT}. Reusing active instance.\n`);
  } catch (_) {
    isReusingActiveEmulator = false;
  }

  if (!isReusingActiveEmulator) {
    if (!fs.existsSync(EMULATOR_JAR)) {
      console.error(`[FATAL] Firestore emulator JAR not found at: ${EMULATOR_JAR}`);
      process.exit(1);
    }

    // Spawn local Firestore emulator process
    console.log(`[EMULATOR] Spawning local Firestore emulator on ${EMULATOR_HOST}:${EMULATOR_PORT}...`);
    emulatorProc = spawn('java', [
      '-jar', EMULATOR_JAR,
      '--host', EMULATOR_HOST,
      '--port', String(EMULATOR_PORT),
      '--rules', RULES_PATH
    ], { stdio: 'pipe' });

    // Monitor unexpected early process exit
    emulatorProc.on('exit', (code, signal) => {
      emulatorClosed = true;
      if (!testFinishedNormally) {
        console.error(`\n[FATAL] Local emulator process exited prematurely (code: ${code}, signal: ${signal})`);
      }
    });

    // Signal & exception hooks ensuring clean termination
    let hookTriggered = false;
    const emergencyTeardown = async (source, err) => {
      if (hookTriggered) return;
      hookTriggered = true;
      console.error(`\n[CLEANUP] Triggered emergency teardown from ${source}${err ? ': ' + err.message : ''}`);
      await terminateEmulator();
      process.exit(1);
    };

    process.once('SIGINT', () => emergencyTeardown('SIGINT'));
    process.once('SIGTERM', () => emergencyTeardown('SIGTERM'));
    process.once('uncaughtException', (err) => emergencyTeardown('uncaughtException', err));

    // Await emulator startup with reliable timeout handling
    await new Promise((resolve, reject) => {
      let resolved = false;
      const timeout = setTimeout(async () => {
        if (!resolved) {
          resolved = true;
          console.error('[EMULATOR] Startup timed out after 15s. Terminating child process...');
          await terminateEmulator();
          reject(new Error('Emulator startup timed out after 15s'));
        }
      }, 15000);

      const checkLine = (data) => {
        const s = data.toString();
        if (s.includes('Dev App Server is now running')) {
          if (!resolved) {
            resolved = true;
            clearTimeout(timeout);
            resolve();
          }
        }
      };

      emulatorProc.stdout.on('data', checkLine);
      emulatorProc.stderr.on('data', checkLine);
      emulatorProc.once('error', async (err) => {
        if (!resolved) {
          resolved = true;
          clearTimeout(timeout);
          console.error(`[EMULATOR] Startup error: ${err.message}`);
          await terminateEmulator();
          reject(err);
        }
      });
    });
  }

  // Probe emulator health via loopback HTTP
  try {
    await probeEmulatorHealth(EMULATOR_HOST, EMULATOR_PORT);
    console.log(`  ✓ Local Firestore emulator active, probed, and responding on ${EMULATOR_HOST}:${EMULATOR_PORT}.\n`);
  } catch (err) {
    console.error(`[FATAL] Emulator health probe failed on ${EMULATOR_HOST}:${EMULATOR_PORT}: ${err.message}`);
    await terminateEmulator();
    process.exit(1);
  }

  let testEnv = null;

  try {
    // Initialize offline test environment
    testEnv = await initializeTestEnvironment({
      projectId: PROJECT_ID,
      firestore: {
        rules: rulesContent,
        host: EMULATOR_HOST,
        port: EMULATOR_PORT
      }
    });

    const ALICE_UID = 'alice_cadet_001';
    const BOB_UID = 'bob_cadet_002';

    // -------------------------------------------------------------
    // Setup initial baseline documents bypassing security rules
    // -------------------------------------------------------------
    await testEnv.withSecurityRulesDisabled(async (context) => {
      const adminDb = context.firestore();
      await adminDb.doc(`users/${ALICE_UID}`).set({
        displayName: 'Alice Mercer',
        email: 'alice@lanzar.me',
        avatarUrl: 'https://cdn.lanzar.me/avatars/alice.png',
        derivedBadges: ['lanzar_id_founder'],
        tokenVersion: 1,
        role: 'customer',
        notificationPreferences: {
          newsletter: true,
          productUpdates: false,
          securityAlerts: true
        },
        updatedAt: new Date()
      });

      await adminDb.doc(`users/${BOB_UID}`).set({
        displayName: 'Bob Vance',
        email: 'bob@lanzar.me',
        avatarUrl: 'https://cdn.lanzar.me/avatars/bob.png',
        derivedBadges: [],
        tokenVersion: 1,
        role: 'customer',
        notificationPreferences: {
          newsletter: false,
          productUpdates: false,
          securityAlerts: false
        },
        updatedAt: new Date()
      });

      // Seed baseline central session & device session for Alice
      await adminDb.doc(`users/${ALICE_UID}/central_sessions/csess_alice_001`).set({
        centralSessionId: 'csess_alice_001',
        uid: ALICE_UID,
        revoked: false,
        createdAt: Math.floor(Date.now() / 1000)
      });

      await adminDb.doc(`users/${ALICE_UID}/session_slots/csess_alice_001__pythos`).set({
        slotId: 'csess_alice_001__pythos',
        clientAppId: 'pythos',
        active: true
      });

      await adminDb.doc(`users/${ALICE_UID}/sessions/sess_alice_dev1`).set({
        sessionId: 'sess_alice_dev1',
        uid: ALICE_UID,
        revoked: false
      });

      await adminDb.doc(`users/${ALICE_UID}/founders/lanzar_id_founder`).set({
        programId: 'lanzar_id_founder',
        active: true
      });
    });

    const aliceDb = testEnv.authenticatedContext(ALICE_UID).firestore();
    const bobDb = testEnv.authenticatedContext(BOB_UID).firestore();
    const unauthDb = testEnv.unauthenticatedContext().firestore();

    // -------------------------------------------------------------
    // Test Category 1: Central SSO Session, Session Slot & Device Session Protection
    // -------------------------------------------------------------
    console.log('[SECTION 1] Central SSO Session, Slot & Device Session Protection');

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}/central_sessions/csess_forged`).set({
        centralSessionId: 'csess_forged',
        uid: ALICE_UID,
        revoked: false
      }));
      assertCheck(true, 'RULE-CS1: Direct client create on /users/{uid}/central_sessions is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-CS1: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}/central_sessions/csess_alice_001`).update({
        revoked: false
      }));
      assertCheck(true, 'RULE-CS2: Direct client update on /users/{uid}/central_sessions is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-CS2: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}/central_sessions/csess_alice_001`).delete());
      assertCheck(true, 'RULE-CS3: Direct client delete on /users/{uid}/central_sessions is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-CS3: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}/central_sessions/csess_alice_001`).get());
      assertCheck(true, 'RULE-CS4: Direct client read of /users/{uid}/central_sessions is DENIED (server-only)');
    } catch (e) {
      assertCheck(false, `RULE-CS4: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}/session_slots/csess_alice_001__hacked`).set({
        clientAppId: 'marketing_site'
      }));
      assertCheck(true, 'RULE-SL1: Direct client create on /users/{uid}/session_slots is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-SL1: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}/session_slots/csess_alice_001__pythos`).update({
        active: false
      }));
      assertCheck(true, 'RULE-SL2: Direct client update on /users/{uid}/session_slots is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-SL2: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}/session_slots/csess_alice_001__pythos`).delete());
      assertCheck(true, 'RULE-SL3: Direct client delete on /users/{uid}/session_slots is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-SL3: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}/session_slots/csess_alice_001__pythos`).get());
      assertCheck(true, 'RULE-SL4: Direct client read of /users/{uid}/session_slots is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-SL4: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}/sessions/sess_alice_dev1`).delete());
      assertCheck(true, 'RULE-DS1: Direct client delete on /users/{uid}/sessions is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-DS1: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}/sessions/sess_alice_dev1`).get());
      assertCheck(true, 'RULE-DS2: Direct client read of /users/{uid}/sessions is DENIED (must use /api/id/sessions)');
    } catch (e) {
      assertCheck(false, `RULE-DS2: Failed with ${e.message}`);
    }

    // -------------------------------------------------------------
    // Test Category 2: Authoritative Founder Programs Direct Access Defense
    // -------------------------------------------------------------
    console.log('\n[SECTION 2] Founder Programs Direct Client Mutation Defense');

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}/founders/pythos_founder`).set({
        programId: 'pythos_founder',
        active: true
      }));
      assertCheck(true, 'RULE-F1: Direct client set() to /users/{uid}/founders is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-F1: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}/founders/lanzar_id_founder`).update({
        active: true
      }));
      assertCheck(true, 'RULE-F2: Direct client update() to /users/{uid}/founders is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-F2: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}/founders/lanzar_id_founder`).delete());
      assertCheck(true, 'RULE-F3: Direct client delete() on /users/{uid}/founders is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-F3: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}/founders/lanzar_id_founder`).get());
      assertCheck(true, 'RULE-F4: Direct client read() on /users/{uid}/founders is DENIED (server-only)');
    } catch (e) {
      assertCheck(false, `RULE-F4: Failed with ${e.message}`);
    }

    // -------------------------------------------------------------
    // Test Category 3: Profile Field Validation & Anti-Tampering Integrity
    // -------------------------------------------------------------
    console.log('\n[SECTION 3] User Profile Anti-Tampering & Granular Field Validation');

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}`).update({
        derivedBadges: ['pythos_founder', 'hacked_badge']
      }));
      assertCheck(true, 'RULE-P1: Client attempt to mutate derivedBadges is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-P1: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}`).update({
        tokenVersion: 999
      }));
      assertCheck(true, 'RULE-P2: Client attempt to mutate tokenVersion is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-P2: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}`).update({
        role: 'admin'
      }));
      assertCheck(true, 'RULE-P3: Client attempt to mutate role is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-P3: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}`).update({
        email: 'hacked_email@attacker.me'
      }));
      assertCheck(true, 'RULE-P4: Direct email modification is DENIED (immutability rule)');
    } catch (e) {
      assertCheck(false, `RULE-P4: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc('users/new_unregistered_cadet').set({
        displayName: 'Attacker Self Created',
        email: 'attacker@lanzar.me'
      }));
      assertCheck(true, 'RULE-P5: Direct client document create() is DENIED (server-only lifecycle)');
    } catch (e) {
      assertCheck(false, `RULE-P5: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}`).delete());
      assertCheck(true, 'RULE-P6: Direct client document delete() is DENIED (must use erasure endpoint)');
    } catch (e) {
      assertCheck(false, `RULE-P6: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}`).update({
        updatedAt: new Date()
      }));
      assertCheck(true, 'RULE-P7: Direct client modification of updatedAt is DENIED (server-controlled timestamp)');
    } catch (e) {
      assertCheck(false, `RULE-P7: Failed with ${e.message}`);
    }

    try {
      await assertSucceeds(aliceDb.doc(`users/${ALICE_UID}`).update({
        displayName: 'Alice Mercer (Updated)',
        avatarUrl: 'https://cdn.lanzar.me/avatars/alice-updated.png'
      }));
      assertCheck(true, 'RULE-P8: Legitimate update of allowlisted fields (displayName, HTTPS avatarUrl) is ALLOWED');
    } catch (e) {
      assertCheck(false, `RULE-P8: Failed with ${e.message}`);
    }

    try {
      await assertSucceeds(aliceDb.doc(`users/${ALICE_UID}`).update({
        avatarUrl: ''
      }));
      assertCheck(true, 'RULE-P9: Clearing avatarUrl with empty string is ALLOWED');
    } catch (e) {
      assertCheck(false, `RULE-P9: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}`).update({
        avatarUrl: 'http://insecure-cdn.lanzar.me/pic.png'
      }));
      assertCheck(true, 'RULE-P10: Insecure HTTP avatarUrl (http://) is strictly DENIED');
    } catch (e) {
      assertCheck(false, `RULE-P10: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}`).update({
        avatarUrl: 'javascript:alert(1)'
      }));
      assertCheck(true, 'RULE-P11: JavaScript scheme in avatarUrl is strictly DENIED');
    } catch (e) {
      assertCheck(false, `RULE-P11: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}`).update({
        avatarUrl: 'https://cdn.lanzar.me/' + 'a'.repeat(2050)
      }));
      assertCheck(true, 'RULE-P12: avatarUrl exceeding 2048 characters is strictly DENIED');
    } catch (e) {
      assertCheck(false, `RULE-P12: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}`).update({
        avatarUrl: 12345
      }));
      assertCheck(true, 'RULE-P13: Non-string avatarUrl is strictly DENIED');
    } catch (e) {
      assertCheck(false, `RULE-P13: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}`).update({
        displayName: ''
      }));
      assertCheck(true, 'RULE-P14: Empty displayName string is strictly DENIED (min 1 char)');
    } catch (e) {
      assertCheck(false, `RULE-P14: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}`).update({
        displayName: 'A'.repeat(101)
      }));
      assertCheck(true, 'RULE-P15: displayName exceeding 100 characters is strictly DENIED');
    } catch (e) {
      assertCheck(false, `RULE-P15: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}`).update({
        displayName: 98765
      }));
      assertCheck(true, 'RULE-P16: Non-string displayName is strictly DENIED');
    } catch (e) {
      assertCheck(false, `RULE-P16: Failed with ${e.message}`);
    }

    try {
      await assertSucceeds(aliceDb.doc(`users/${ALICE_UID}`).update({
        notificationPreferences: {
          newsletter: true,
          productUpdates: false,
          securityAlerts: true
        }
      }));
      assertCheck(true, 'RULE-P17: Valid notificationPreferences with allowed boolean keys is ALLOWED');
    } catch (e) {
      assertCheck(false, `RULE-P17: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}`).update({
        notificationPreferences: {
          newsletter: true,
          marketingTrackingConsent: true
        }
      }));
      assertCheck(true, 'RULE-P18: notificationPreferences containing unallowlisted key is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-P18: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}`).update({
        notificationPreferences: {
          newsletter: 'subscribed'
        }
      }));
      assertCheck(true, 'RULE-P19: notificationPreferences with non-boolean value is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-P19: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}`).update({
        notificationPreferences: 'all_enabled'
      }));
      assertCheck(true, 'RULE-P20: Non-map notificationPreferences is strictly DENIED');
    } catch (e) {
      assertCheck(false, `RULE-P20: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}`).update({
        displayName: 'Alice Valid Name',
        role: 'admin'
      }));
      assertCheck(true, 'RULE-P21: Partial document attack sneaking in role:admin alongside valid field is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-P21: Failed with ${e.message}`);
    }

    try {
      await assertSucceeds(aliceDb.doc(`users/${ALICE_UID}`).update({
        bio: 'Senior Systems Architect and Mission Specialist'
      }));
      assertCheck(true, 'RULE-P22: Legitimate update of bio (<= 280 chars) is ALLOWED');
    } catch (e) {
      assertCheck(false, `RULE-P22: Failed with ${e.message}`);
    }

    try {
      await assertSucceeds(aliceDb.doc(`users/${ALICE_UID}`).update({
        bio: ''
      }));
      assertCheck(true, 'RULE-P23: Clearing bio with empty string is ALLOWED');
    } catch (e) {
      assertCheck(false, `RULE-P23: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}`).update({
        bio: 'B'.repeat(281)
      }));
      assertCheck(true, 'RULE-P24: bio exceeding 280 characters is strictly DENIED');
    } catch (e) {
      assertCheck(false, `RULE-P24: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}`).update({
        bio: 12345
      }));
      assertCheck(true, 'RULE-P25: Non-string bio is strictly DENIED');
    } catch (e) {
      assertCheck(false, `RULE-P25: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}`).update({
        bio: 'Valid bio update',
        role: 'admin'
      }));
      assertCheck(true, 'RULE-P26: Partial document attack sneaking in role:admin alongside valid bio is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-P26: Failed with ${e.message}`);
    }

    // -------------------------------------------------------------
    // Test Category 4: Server-Only Collections & Security Metadata
    // -------------------------------------------------------------
    console.log('\n[SECTION 4] Server-Only Security Collections & Audit Stream Protection');

    try {
      await assertFails(aliceDb.doc('security_logs/fake_log_001').set({
        actorUid: ALICE_UID,
        action: 'falsified.event',
        timestamp: new Date().toISOString()
      }));
      assertCheck(true, 'RULE-S1: Direct client write to /security_logs is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-S1: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc('security_logs/fake_log_001').get());
      assertCheck(true, 'RULE-S2: Direct client read of /security_logs is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-S2: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`user_security/${ALICE_UID}`).get());
      assertCheck(true, 'RULE-S3: Direct client read of /user_security is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-S3: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`user_security/${ALICE_UID}`).set({
        accountStatus: 'active',
        role: 'admin'
      }));
      assertCheck(true, 'RULE-S4: Direct client write to /user_security is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-S4: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`mfa_factors/${ALICE_UID}`).get());
      assertCheck(true, 'RULE-S5: Direct client read of /mfa_factors is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-S5: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`mfa_factors/${ALICE_UID}`).set({
        enabled: false,
        totpSecret: 'tampered'
      }));
      assertCheck(true, 'RULE-S6: Direct client write to /mfa_factors is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-S6: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc('phone_otps/otp_123').get());
      assertCheck(true, 'RULE-S7: Direct client read of /phone_otps is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-S7: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc('phone_otps/otp_123').set({
        code: '123456',
        phone: '+15085551234'
      }));
      assertCheck(true, 'RULE-S8: Direct client write to /phone_otps is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-S8: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc('unknown_arbitrary_collection/doc1').get());
      assertCheck(true, 'RULE-S9: Direct client read of unmapped collection is DENIED (default-deny)');
    } catch (e) {
      assertCheck(false, `RULE-S9: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc('custom_col/doc1/deep_subcol/doc2').set({ test: true }));
      assertCheck(true, 'RULE-S10: Direct client write to deeply nested unmapped path is DENIED (default-deny)');
    } catch (e) {
      assertCheck(false, `RULE-S10: Failed with ${e.message}`);
    }

    // -------------------------------------------------------------
    // Test Category 5: Multi-Tenant Boundary Isolation & Anonymous Access Defense
    // -------------------------------------------------------------
    console.log('\n[SECTION 5] Multi-Tenant Boundary Isolation & Anonymous Access Defense');

    try {
      await assertFails(bobDb.doc(`users/${ALICE_UID}`).get());
      assertCheck(true, 'RULE-C1: Cross-user data harvesting: Bob reading Alice profile is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-C1: Failed with ${e.message}`);
    }

    try {
      await assertFails(bobDb.doc(`users/${ALICE_UID}`).update({
        displayName: 'Bob was here'
      }));
      assertCheck(true, 'RULE-C2: Cross-user account tampering: Bob updating Alice profile is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-C2: Failed with ${e.message}`);
    }

    try {
      await assertFails(bobDb.doc(`users/${ALICE_UID}/central_sessions/csess_alice_001`).get());
      assertCheck(true, 'RULE-C3: Cross-user nested harvesting: Bob reading Alice central_sessions is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-C3: Failed with ${e.message}`);
    }

    try {
      await assertFails(bobDb.doc(`users/${ALICE_UID}/central_sessions/csess_alice_001`).delete());
      assertCheck(true, 'RULE-C4: Cross-user nested tampering: Bob deleting Alice central_sessions is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-C4: Failed with ${e.message}`);
    }

    try {
      await assertFails(bobDb.doc(`users/${ALICE_UID}/session_slots/csess_alice_001__pythos`).set({ active: false }));
      assertCheck(true, 'RULE-C5: Cross-user nested tampering: Bob mutating Alice session_slots is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-C5: Failed with ${e.message}`);
    }

    try {
      await assertFails(unauthDb.doc(`users/${ALICE_UID}`).get());
      assertCheck(true, 'RULE-C6: Unauthenticated anonymous client reading Alice profile is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-C6: Failed with ${e.message}`);
    }

    try {
      await assertFails(unauthDb.doc(`users/${ALICE_UID}`).update({ displayName: 'Anonymous Hacker' }));
      assertCheck(true, 'RULE-C7: Unauthenticated anonymous client updating Alice profile is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-C7: Failed with ${e.message}`);
    }

    try {
      await assertFails(unauthDb.doc('phone_otps/fake_otp').set({ code: '999999' }));
      assertCheck(true, 'RULE-C8: Unauthenticated anonymous client writing to /phone_otps is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-C8: Failed with ${e.message}`);
    }

    testFinishedNormally = true;

  } finally {
    // Teardown offline environment
    if (testEnv) {
      await testEnv.cleanup().catch(() => {});
    }
    // Shut down emulator process with termination wait
    await terminateEmulator();
  }

  console.log('\n================================================================');
  console.log(`  LEVEL 3 SECURITY RULES RESULTS: ${passedTests} PASSED, ${failedTests} FAILED`);
  console.log('================================================================');

  if (failedTests > 0) process.exit(1);
  else process.exit(0);
}

runRulesTestSuite().catch(async (err) => {
  console.error('[FATAL] Rules test suite execution error:', err);
  await terminateEmulator();
  process.exit(1);
});
