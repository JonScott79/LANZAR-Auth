/**
 * test-level3-firestore-rules.cjs
 *
 * LANZAR ID — Level 3 Firestore Security Rules Verification Battery
 * Target Specification: LID-ARCH-REV-015 §3.3 (Customer Profile Schema & Strict Security Rules)
 *
 * Verifies that client SDK operations (with customer credentials or unauthenticated)
 * are strictly constrained by firestore.rules, independently of the backend Admin SDK:
 * - Direct writes to /users/{uid}/founders are REJECTED.
 * - Injecting derivedBadges, tokenVersion, role, or arbitrary keys is REJECTED.
 * - Mutating email directly is REJECTED.
 * - Writes to /security_logs, /user_security, sessions, and mfa_factors are REJECTED.
 * - Cross-user data harvesting and unauthenticated access are REJECTED.
 * - Legitimate profile updates complying with the strict field allowlist SUCCEED.
 */

const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

module.paths.push(path.resolve(__dirname, 'auth-backend/node_modules'));
module.paths.push(path.resolve(__dirname, '../node_modules'));

const {
  initializeTestEnvironment,
  assertFails,
  assertSucceeds
} = require('@firebase/rules-unit-testing');

const PROJECT_ID = 'demo-lanzar-rules-test';
const RULES_PATH = path.resolve(__dirname, '../firestore.rules');
const EMULATOR_JAR = path.resolve(process.env.USERPROFILE, '.cache/firebase/emulators/cloud-firestore-emulator-v1.19.6.jar');
const EMULATOR_PORT = 8088;

let passedTests = 0;
let failedTests = 0;

function assertCheck(passed, description) {
  if (passed) {
    console.log(`  ✓ [PASS] ${description}`);
    passedTests++;
  } else {
    console.error(`  ❌ [FAIL] ${description}`);
    failedTests++;
  }
}

async function runRulesTestSuite() {
  console.log('================================================================');
  console.log('  LANZAR ID — Level 3 Firestore Security Rules Test Battery');
  console.log(`  Target Project:     ${PROJECT_ID} [OFFLINE LOCAL EMULATOR]`);
  console.log(`  Rules File:         firestore.rules`);
  console.log(`  Emulator Host:      127.0.0.1:${EMULATOR_PORT}`);
  console.log('  Cloud Access:       STRICTLY ZERO (demo- prefix enforces offline)');
  console.log('================================================================\n');

  if (!fs.existsSync(RULES_PATH)) {
    console.error(`[FATAL] Rules file not found at: ${RULES_PATH}`);
    process.exit(1);
  }

  if (!fs.existsSync(EMULATOR_JAR)) {
    console.error(`[FATAL] Firestore emulator JAR not found at: ${EMULATOR_JAR}`);
    process.exit(1);
  }

  const rulesContent = fs.readFileSync(RULES_PATH, 'utf8');

  // Spawn local Firestore emulator process
  console.log('[EMULATOR] Spawning local Firestore emulator on 127.0.0.1:' + EMULATOR_PORT + '...');
  const emulatorProc = spawn('java', [
    '-jar', EMULATOR_JAR,
    '--host', '127.0.0.1',
    '--port', String(EMULATOR_PORT),
    '--rules', RULES_PATH
  ], { stdio: 'pipe' });

  // Await emulator startup
  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Emulator startup timed out after 15s')), 15000);
    const checkLine = (data) => {
      const s = data.toString();
      if (s.includes('Dev App Server is now running') || s.includes('Started WebSocket server')) {
        clearTimeout(timeout);
        resolve();
      }
    };
    emulatorProc.stdout.on('data', checkLine);
    emulatorProc.stderr.on('data', checkLine);
    emulatorProc.on('error', (err) => {
      clearTimeout(timeout);
      reject(err);
    });
  });

  console.log('  ✓ Local Firestore emulator active and listening.\n');

  process.env.FIRESTORE_EMULATOR_HOST = `127.0.0.1:${EMULATOR_PORT}`;

  let testEnv = null;

  try {
    // Initialize offline test environment
    testEnv = await initializeTestEnvironment({
      projectId: PROJECT_ID,
      firestore: {
        rules: rulesContent,
        host: '127.0.0.1',
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
    });

    const aliceDb = testEnv.authenticatedContext(ALICE_UID).firestore();
    const bobDb = testEnv.authenticatedContext(BOB_UID).firestore();
    const unauthDb = testEnv.unauthenticatedContext().firestore();

    // -------------------------------------------------------------
    // Test Category 1: Authoritative Founder Programs Direct Access Defense
    // -------------------------------------------------------------
    console.log('[SECTION 1] Founder Programs Direct Client Mutation Defense');

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

    // -------------------------------------------------------------
    // Test Category 2: Profile Anti-Tampering & Allowlist Integrity
    // -------------------------------------------------------------
    console.log('\n[SECTION 2] User Profile Anti-Tampering & Strict Allowlist Enforcement');

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
      await assertSucceeds(aliceDb.doc(`users/${ALICE_UID}`).update({
        displayName: 'Alice Mercer (Updated)',
        avatarUrl: 'https://cdn.lanzar.me/avatars/alice-updated.png'
      }));
      assertCheck(true, 'RULE-P7: Legitimate update of allowlisted fields (displayName, HTTPS avatarUrl) is ALLOWED');
    } catch (e) {
      assertCheck(false, `RULE-P7: Failed with ${e.message}`);
    }

    try {
      await assertSucceeds(aliceDb.doc(`users/${ALICE_UID}`).update({
        avatarUrl: ''
      }));
      assertCheck(true, 'RULE-P8: Clearing avatarUrl with empty string is ALLOWED');
    } catch (e) {
      assertCheck(false, `RULE-P8: Failed with ${e.message}`);
    }

    try {
      await assertFails(aliceDb.doc(`users/${ALICE_UID}`).update({
        avatarUrl: 'http://insecure-cdn.lanzar.me/pic.png'
      }));
      assertCheck(true, 'RULE-P9: Non-HTTPS avatarUrl (http://) is strictly DENIED');
    } catch (e) {
      assertCheck(false, `RULE-P9: Failed with ${e.message}`);
    }

    // -------------------------------------------------------------
    // Test Category 3: Server-Only Collections & Security Metadata
    // -------------------------------------------------------------
    console.log('\n[SECTION 3] Server-Only Security Collections & Audit Stream Protection');

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
      await assertFails(aliceDb.doc(`users/${ALICE_UID}/sessions/fake_sess_01`).set({
        sessionId: 'fake_sess_01',
        revoked: false
      }));
      assertCheck(true, 'RULE-S5: Direct client write to /users/{uid}/sessions is DENIED');
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

    // -------------------------------------------------------------
    // Test Category 4: Cross-User Isolation & Unauthenticated Defense
    // -------------------------------------------------------------
    console.log('\n[SECTION 4] Multi-Tenant Boundary Isolation & Anonymous Access Defense');

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
      await assertFails(unauthDb.doc(`users/${ALICE_UID}`).get());
      assertCheck(true, 'RULE-C3: Unauthenticated anonymous client reading Alice profile is DENIED');
    } catch (e) {
      assertCheck(false, `RULE-C3: Failed with ${e.message}`);
    }

  } finally {
    // Teardown offline environment
    if (testEnv) {
      await testEnv.cleanup();
    }
    // Shut down emulator process
    console.log('\n[EMULATOR] Shutting down local Firestore emulator...');
    emulatorProc.kill();
  }

  console.log('\n================================================================');
  console.log(`  LEVEL 3 SECURITY RULES RESULTS: ${passedTests} PASSED, ${failedTests} FAILED`);
  console.log('================================================================');

  if (failedTests > 0) process.exit(1);
  else process.exit(0);
}

runRulesTestSuite().catch(err => {
  console.error('[FATAL] Rules test suite execution error:', err);
  process.exit(1);
});
