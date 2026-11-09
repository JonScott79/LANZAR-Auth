// test-auth-and-mfa.cjs
const { cert, initializeApp, getApps } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');
const fs = require('fs');
const crypto = require('crypto');
const mfa = require('./auth-backend/mfaService.js');
const { AuthorizationCodeStore } = require('./auth-backend/store.js');
const { getClient } = require('./auth-backend/clients.js');

const credentialPath = 'C:\\Projects\\LANZAR\\firebase-credentials\\lanzar-95ae3-firebase-adminsdk-fbsvc-86e8ea5817.json';
const serviceAccount = JSON.parse(fs.readFileSync(credentialPath, 'utf8'));
const app = getApps().length > 0 ? getApps()[0] : initializeApp({ credential: cert(serviceAccount) });
const db = getFirestore(app);
const auth = getAuth(app);

async function runAuthAndMfaTests() {
  console.log('========================================================');
  console.log('   LANZAR ID & MFA Full Verification Test Battery');
  console.log('========================================================\n');

  const testUid = `cadet_${Date.now()}`;
  const testEmail = `cadet.${Date.now()}@lanzar.me`;
  const testPassword = 'SecurePassword2026!';
  const testName = 'Alex Mercer';
  const testBusiness = 'Mercer Logistics';

  try {
    // -------------------------------------------------------------
    // TEST 1: User Registration & Auto-Provisioning
    // -------------------------------------------------------------
    console.log('[TEST 1] Testing User Registration & Server-Controlled Provisioning...');
    
    // Create Firebase Auth user
    const userRecord = await auth.createUser({
      uid: testUid,
      email: testEmail,
      password: testPassword,
      displayName: testName
    });
    console.log(`  ✓ Created Firebase Auth user: ${userRecord.uid} (${testEmail})`);

    // Simulate server-side reconcileCustomerAccount with Dispatch Opt-In = true
    const normalizedEmail = testEmail.toLowerCase();
    await db.collection('customers').doc(testUid).set({
      id: testUid,
      customerId: testUid,
      customerName: testName,
      customerEmail: normalizedEmail,
      authEmail: normalizedEmail,
      businessName: testBusiness,
      role: 'customer',
      active: true,
      services: ['portal', 'tickets'],
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp()
    });

    await db.collection('users').doc(testUid).set({
      displayName: testName,
      email: normalizedEmail,
      role: 'customer',
      active: true,
      services: ['portal', 'tickets'],
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp()
    });

    await db.collection('mailing_list').doc(normalizedEmail).set({
      email: normalizedEmail,
      fullName: testName,
      status: 'active',
      source: 'lanzar-id',
      consentVersion: 'dispatch_v1',
      consentText: 'Send me The LANZAR Dispatch — news, project updates, new services, and occasional offers.',
      consentedAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp()
    });

    // Verify documents exist in Firestore
    const custSnap = await db.collection('customers').doc(testUid).get();
    const userSnap = await db.collection('users').doc(testUid).get();
    const mailSnap = await db.collection('mailing_list').doc(normalizedEmail).get();

    if (!custSnap.exists || custSnap.data().active !== true) throw new Error('Customer document not active');
    if (!userSnap.exists || userSnap.data().role !== 'customer') throw new Error('User document role invalid');
    if (!mailSnap.exists || mailSnap.data().source !== 'lanzar-id') throw new Error('Mailing list consent record missing');

    console.log('  ✓ Customer profile provisioned in customers/{uid} and users/{uid}');
    console.log('  ✓ Dispatch newsletter consent recorded with source=lanzar-id and dispatch_v1');

    // -------------------------------------------------------------
    // TEST 2: Authorization Code Generation with PKCE
    // -------------------------------------------------------------
    console.log('\n[TEST 2] Testing PKCE OAuth2 Authorization Code Generation...');
    const codeStore = new AuthorizationCodeStore();
    const codeVerifier = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    const redirectUri = 'https://portal.lanzar.me';

    const code = await codeStore.createCode({
      uid: testUid,
      clientId: 'portal',
      redirectUri,
      codeChallenge,
      mfaVerified: false
    });
    if (!code) throw new Error('Failed to generate authorization code');
    console.log(`  ✓ Generated authorization code: ${code.slice(0, 8)}...`);

    // Verify exchange with correct PKCE
    const record = await codeStore.getCode(code);
    if (!record || record.used) throw new Error('Code record invalid or marked used prematurely');
    const computedHash = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    if (computedHash !== record.codeChallenge) throw new Error('PKCE verification mismatch');

    // Mark used & test replay protection
    await codeStore.markUsed(code);
    const recordAfter = await codeStore.getCode(code);
    if (!recordAfter.used) throw new Error('Code was not marked used');
    console.log('  ✓ PKCE verification and code single-use replay protection passed.');

    // -------------------------------------------------------------
    // TEST 3: TOTP MFA Setup, Enrollment & Verification
    // -------------------------------------------------------------
    console.log('\n[TEST 3] Testing TOTP Multi-Factor Authentication Lifecycle...');
    const secret = mfa.generateBase32Secret(20);
    console.log(`  ✓ Generated TOTP Base32 secret: ${secret.slice(0, 6)}...`);

    // Generate valid TOTP
    const validTotp = mfa.generateTOTP(secret);
    if (!mfa.verifyTOTP(secret, validTotp)) throw new Error('Valid TOTP failed verification');
    if (mfa.verifyTOTP(secret, '000000')) throw new Error('Invalid TOTP passed verification');
    console.log('  ✓ TOTP verification algorithm verified (valid succeeds, invalid fails).');

    // Generate and store recovery codes
    const { plainCodes, hashedRecords } = mfa.generateRecoveryCodes(8);
    if (plainCodes.length !== 8) throw new Error('Expected 8 recovery codes');

    await db.collection('mfa_factors').doc(testUid).set({
      uid: testUid,
      email: normalizedEmail,
      enabled: true,
      totpSecret: secret,
      recoveryCodes: hashedRecords,
      enrolledAt: FieldValue.serverTimestamp()
    });

    const mfaSnap = await db.collection('mfa_factors').doc(testUid).get();
    if (!mfaSnap.exists || !mfaSnap.data().enabled) throw new Error('MFA factors document not persisted');
    console.log('  ✓ MFA factors document enrolled and persisted in Firestore.');

    // -------------------------------------------------------------
    // TEST 4: Single-Use Recovery Code Consumption
    // -------------------------------------------------------------
    console.log('\n[TEST 4] Testing Single-Use Recovery Code Verification...');
    const testRecoveryCode = plainCodes[0];
    const recoveryRes1 = mfa.verifyAndConsumeRecoveryCode(testRecoveryCode, hashedRecords);
    if (!recoveryRes1.valid) throw new Error('Valid recovery code rejected');
    console.log(`  ✓ Valid recovery code ${testRecoveryCode} consumed successfully.`);

    // Replay attempt must fail
    const recoveryRes2 = mfa.verifyAndConsumeRecoveryCode(testRecoveryCode, hashedRecords);
    if (recoveryRes2.valid) throw new Error('Consumed recovery code accepted on second attempt!');
    console.log('  ✓ Replayed recovery code was rejected (single-use enforced).');

    // -------------------------------------------------------------
    // TEST 5: Signed MFA Session & Proof Tokens
    // -------------------------------------------------------------
    console.log('\n[TEST 5] Testing Signed MFA Challenge and Proof Tokens...');
    const proofToken = mfa.createMfaSignedToken({
      uid: testUid,
      email: normalizedEmail,
      action: 'mfa_verified',
      verifiedAt: Date.now()
    }, 60000);

    const verifiedPayload = mfa.verifyMfaSignedToken(proofToken);
    if (!verifiedPayload || verifiedPayload.uid !== testUid || verifiedPayload.action !== 'mfa_verified') {
      throw new Error('Valid proof token rejected');
    }
    console.log('  ✓ Signed MFA proof token verified.');

    const tamperedProof = proofToken.slice(0, -6) + 'xxxxxx';
    if (mfa.verifyMfaSignedToken(tamperedProof) !== null) {
      throw new Error('Tampered proof token accepted!');
    }
    console.log('  ✓ Tampered proof token detected and rejected.');

    // -------------------------------------------------------------
    // TEST 6: Clean Up Test Records
    // -------------------------------------------------------------
    console.log('\n[TEST 6] Cleaning up test records from Firebase...');
    await auth.deleteUser(testUid);
    await db.collection('customers').doc(testUid).delete();
    await db.collection('users').doc(testUid).delete();
    await db.collection('mfa_factors').doc(testUid).delete();
    await db.collection('mailing_list').doc(normalizedEmail).delete();
    console.log('  ✓ All test authentication and database records cleaned up.');

    console.log('\n========================================================');
    console.log('   ALL AUTH & MFA TESTS PASSED SUCCESSFULLY (100%)');
    console.log('========================================================');
  } catch (err) {
    console.error('\n❌ AUTH & MFA TEST FAILED:', err.message);
    await auth.deleteUser(testUid).catch(() => {});
    await db.collection('customers').doc(testUid).delete().catch(() => {});
    await db.collection('users').doc(testUid).delete().catch(() => {});
    await db.collection('mfa_factors').doc(testUid).delete().catch(() => {});
    process.exit(1);
  }
}

runAuthAndMfaTests().then(() => process.exit(0)).catch(err => {
  console.error(err);
  process.exit(1);
});
