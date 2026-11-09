/**
 * test-level3-firestore-rules.cjs
 *
 * LANZAR ID — Level 3 Firestore Security Rules Verification Battery (Step 4.1 Audit & Completion)
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
 */

const path = require('path');
const fs = require('fs');
const http = require('http');
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
const EMULATOR_HOST = '127.0.0.1';
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

async function probeEmulatorHealth(host, port) {
  return new Promise((resolve, reject) => {
    const req = http.get(`http://${host}:${port}/`, (res) => {
      resolve(res.statusCode);
    });
    req.on('error', reject);
    req.setTimeout(2000, () => {
      req.destroy();
      reject(new Error('Emulator HTTP probe timed out'));
    });
  });
}

async function runRulesTestSuite() {
  console.log('================================================================');
  console.log('  LANZAR ID — Level 3 Firestore Security Rules Test Battery');
  console.log('  Step 4.1 Audit & Full Security Coverage Completion');
  console.log(`  Target Project:     ${PROJECT_ID} [OFFLINE LOCAL EMULATOR]`);
  console.log(`  Rules File:         firestore.rules`);
  console.log(`  Emulator Host:      ${EMULATOR_HOST}:${EMULATOR_PORT}`);
  console.log('  Cloud Access:       STRICTLY ZERO (demo- prefix enforces offline)');
  console.log('================================================================\n');

  // Isolation Guard 1: Verify credentials environment
  if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    console.warn(`[ISOLATION] Stripping GOOGLE_APPLICATION_CREDENTIALS for rules testing.`);
    delete process.env.GOOGLE_APPLICATION_CREDENTIALS;
  }

  // Isolation Guard 2: Verify demo- prefix
  if (!PROJECT_ID.startsWith('demo-')) {
    console.error(`[FATAL] Rules test project ID must start with "demo-" to ensure offline mode: ${PROJECT_ID}`);
    process.exit(1);
  }

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
  console.log(`[EMULATOR] Spawning local Firestore emulator on ${EMULATOR_HOST}:${EMULATOR_PORT}...`);
  const emulatorProc = spawn('java', [
    '-jar', EMULATOR_JAR,
    '--host', EMULATOR_HOST,
    '--port', String(EMULATOR_PORT),
    '--rules', RULES_PATH
  ], { stdio: 'pipe' });

  // Clean shutdown handlers
  let cleanedUp = false;
  const cleanupProcess = () => {
    if (!cleanedUp && emulatorProc) {
      cleanedUp = true;
      try {
        emulatorProc.kill();
      } catch (_) {}
    }
  };

  process.on('SIGINT', () => { cleanupProcess(); process.exit(1); });
  process.on('SIGTERM', () => { cleanupProcess(); process.exit(1); });
  process.on('uncaughtException', (err) => {
    console.error('[UNCAUGHT EXCEPTION]', err);
    cleanupProcess();
    process.exit(1);
  });

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

  // Probe emulator health via loopback HTTP
  try {
    await probeEmulatorHealth(EMULATOR_HOST, EMULATOR_PORT);
    console.log(`  ✓ Local Firestore emulator active, probed, and responding on ${EMULATOR_HOST}:${EMULATOR_PORT}.\n`);
  } catch (err) {
    console.error(`[FATAL] Emulator health probe failed: ${err.message}`);
    cleanupProcess();
    process.exit(1);
  }

  process.env.FIRESTORE_EMULATOR_HOST = `${EMULATOR_HOST}:${EMULATOR_PORT}`;

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

  } finally {
    // Teardown offline environment
    if (testEnv) {
      await testEnv.cleanup();
    }
    // Shut down emulator process
    console.log('\n[EMULATOR] Shutting down local Firestore emulator...');
    cleanupProcess();
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
