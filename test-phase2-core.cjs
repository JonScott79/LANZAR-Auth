// test-phase2-core.cjs
// Comprehensive Automated Test Battery for LANZAR ID Core Services (Phase 2 + Amendments #001 & #002)

const { cert, initializeApp, getApps } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');
const fs = require('fs');
const crypto = require('crypto');

const {
    generateBase32Secret,
    generateTOTP,
    verifyTOTP,
    encryptTotpSecret,
    decryptTotpSecret,
    stagePendingEnrollment,
    getPendingEnrollment,
    clearPendingEnrollment,
    generateRecoveryCodes,
    verifyAndConsumeRecoveryCode
} = require('./auth-backend/mfaService.js');

const { SessionService } = require('./auth-backend/sessionService.js');
const { FounderService } = require('./auth-backend/founderService.js');
const { ProfileService } = require('./auth-backend/profileService.js');
const { SMSService, MockSMSProvider } = require('./auth-backend/smsService.js');
const { recordSecurityEvent, sanitizeAuditDetails } = require('./auth-backend/auditService.js');

const credentialPath = process.env.FIREBASE_CREDENTIAL_PATH || 'C:\\Projects\\LANZAR\\firebase-credentials\\lanzar-95ae3-firebase-adminsdk-fbsvc-86e8ea5817.json';
const serviceAccount = JSON.parse(fs.readFileSync(credentialPath, 'utf8'));
const app = getApps().length > 0 ? getApps()[0] : initializeApp({ credential: cert(serviceAccount) });
const db = getFirestore(app);
const auth = getAuth(app);

const sessionService = new SessionService(db, auth);
const founderService = new FounderService(db);
const profileService = new ProfileService(db, auth, sessionService);
const smsService = new SMSService(db);

let passCount = 0;
let failCount = 0;

function assert(condition, testName) {
    if (condition) {
        console.log(`  ✓ [PASS] ${testName}`);
        passCount++;
    } else {
        console.error(`  ✗ [FAIL] ${testName}`);
        failCount++;
    }
}

async function runPhase2Tests() {
    console.log('================================================================');
    console.log('  LANZAR ID Core Services — Phase 2 Quality Gate Test Battery   ');
    console.log('  Includes Amendment #001 (Universal TOTP) & Amendment #002     ');
    console.log('================================================================\n');

    const testUid = `test_cadet_${Date.now()}`;
    const testEmail = `cadet.${Date.now()}@lanzar.me`;
    const testName = 'Commander Alex';

    try {
        // Create genuine Firebase Auth cadet record for realistic verification
        await auth.createUser({
            uid: testUid,
            email: testEmail,
            displayName: testName,
            password: 'TestPassword2026!'
        });
        console.log(`  ✓ Initialized test Firebase Auth cadet: ${testUid} (${testEmail})`);
        // -------------------------------------------------------------
        // SUITE 1: Universal TOTP Authenticator Compatibility (Amendment #001)
        // -------------------------------------------------------------
        console.log('[SUITE 1] Universal RFC 6238 TOTP Engine & AES-256-GCM Storage');

        const base32Secret = generateBase32Secret(20);
        assert(base32Secret.length === 32, 'Base32 secret generated with 32 characters (20 bytes)');

        // RFC 6238 standard algorithm check
        const currentCode = generateTOTP(base32Secret);
        assert(/^\d{6}$/.test(currentCode), `Generated valid 6-digit TOTP code: ${currentCode}`);

        // Verification check
        const isValid = verifyTOTP(base32Secret, currentCode, testUid);
        assert(isValid === true, 'Current code validates successfully against secret');

        // Replay Protection Check
        const isReplayValid = verifyTOTP(base32Secret, currentCode, testUid);
        assert(isReplayValid === false, 'Replaying the same 6-digit code within validity window is REJECTED');

        // Unconfirmed secret staging & expiration check
        stagePendingEnrollment(testUid, base32Secret);
        assert(getPendingEnrollment(testUid) === base32Secret, 'Pending unconfirmed secret staged in cache');
        clearPendingEnrollment(testUid);
        assert(getPendingEnrollment(testUid) === null, 'Pending unconfirmed secret cleared after completion');

        // AES-256-GCM Encryption at rest check
        const encryptedEnvelope = encryptTotpSecret(base32Secret);
        assert(encryptedEnvelope.encryptedSecret && encryptedEnvelope.iv && encryptedEnvelope.tag, 'Secret encrypted with AES-256-GCM (contains ciphertext, iv, auth tag)');
        assert(!encryptedEnvelope.encryptedSecret.includes(base32Secret), 'Ciphertext does not expose plaintext Base32 secret');

        const decryptedSecret = decryptTotpSecret(encryptedEnvelope);
        assert(decryptedSecret === base32Secret, 'AES-256-GCM decryption recovers original Base32 secret cleanly');

        // Single-use recovery codes check
        const { plainCodes, hashedRecords } = generateRecoveryCodes(8);
        assert(plainCodes.length === 8 && hashedRecords.length === 8, 'Generated 8 single-use recovery codes with hashes');
        const codeToTest = plainCodes[0];
        const consumeResult = verifyAndConsumeRecoveryCode(codeToTest, hashedRecords);
        assert(consumeResult.valid === true, 'First recovery code consumed successfully');
        const reuseResult = verifyAndConsumeRecoveryCode(codeToTest, hashedRecords);
        assert(reuseResult.valid === false, 'Reusing consumed recovery code is strictly rejected');

        // -------------------------------------------------------------
        // SUITE 2: Phone Authentication & Provider Abstraction (Amendment #002)
        // -------------------------------------------------------------
        console.log('\n[SUITE 2] Phone Authentication Infrastructure & Rate Limiting (Amendment #002)');

        // E.164 normalization
        const normalized = smsService.normalizePhoneNumber('508-555-1234');
        assert(normalized === '+15085551234', `Normalized raw input '508-555-1234' to E.164: ${normalized}`);

        // Country code geo-whitelisting defense
        let blocked = false;
        try {
            smsService.normalizePhoneNumber('+447911123456'); // UK number (not whitelisted)
        } catch (e) {
            blocked = true;
        }
        assert(blocked === true, 'Non-whitelisted country prefix correctly rejected at boundary');

        // Mock SMS Provider test
        const otpDispatch = await smsService.sendVerificationOTP(testUid, '+15085559876', '127.0.0.1');
        assert(otpDispatch.success === true && otpDispatch.phoneNumber === '+15085559876', 'MockSMSProvider simulated OTP dispatch without external carrier charges');

        // Rate limiting test (requesting twice within 60s)
        let rateLimited = false;
        try {
            await smsService.sendVerificationOTP(testUid, '+15085559876', '127.0.0.1');
        } catch (e) {
            rateLimited = true;
        }
        assert(rateLimited === true, 'Requesting OTP twice within 60 seconds is rate-limited');

        // -------------------------------------------------------------
        // SUITE 3: Session Security & Server-Enforced Revocation
        // -------------------------------------------------------------
        console.log('\n[SUITE 3] Server-Side Session Registry & Revocation Gates');

        // Create 2 test sessions for user
        const sess1 = await sessionService.createSession({
            uid: testUid,
            clientId: 'portal',
            ipAddress: '198.51.100.1',
            userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
            deviceName: 'MacBook Pro'
        });
        const sess2 = await sessionService.createSession({
            uid: testUid,
            clientId: 'pythos',
            ipAddress: '198.51.100.2',
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            deviceName: 'ThinkPad'
        });

        assert(sess1.sessionId && sess2.sessionId, 'Created individual session documents in Firestore');

        // Verify sessions are active
        const isSess1Revoked = await sessionService.isSessionRevoked(testUid, sess1.sessionId);
        assert(isSess1Revoked === false, 'Device 1 session is active and verified by server');

        // Individual session revocation test
        await sessionService.revokeSession(testUid, sess1.sessionId, testUid);
        const isSess1RevokedAfter = await sessionService.isSessionRevoked(testUid, sess1.sessionId);
        assert(isSess1RevokedAfter === true, 'Device 1 session revoked on server; subsequent API checks fail');

        // Device 2 should remain active
        const isSess2StillActive = await sessionService.isSessionRevoked(testUid, sess2.sessionId);
        assert(isSess2StillActive === false, 'Device 2 session remains active independently (individual scoping works)');

        // Global Revocation test ("Sign Out Everywhere")
        const globalRevokeResult = await sessionService.revokeAllSessions(testUid, testUid);
        assert(globalRevokeResult.success === true, 'Global revocation executed successfully');

        const isSess2RevokedGlobally = await sessionService.isSessionRevoked(testUid, sess2.sessionId);
        assert(isSess2RevokedGlobally === true, 'Device 2 session terminated by global revocation kill switch');

        // Check tokenVersion increment
        const userDocAfterGlobal = await db.collection('users').doc(testUid).get();
        assert(userDocAfterGlobal.exists && userDocAfterGlobal.data().tokenVersion > 0, 'tokenVersion successfully incremented in Firestore');

        // -------------------------------------------------------------
        // SUITE 4: Authoritative Founder Programs & Derived Badges
        // -------------------------------------------------------------
        console.log('\n[SUITE 4] Authoritative Founder Programs & Derived Badges Invariant');

        // Grant Pythos Founder
        const grant1 = await founderService.grantFounderDesignation({
            uid: testUid,
            programId: 'pythos_founder',
            founderNumber: 42,
            title: 'Pythos Founding Scholar',
            grantReason: 'Quality gate testing pioneer',
            grantedBy: 'admin_test_operator'
        });
        assert(grant1.success === true && grant1.derivedBadges.includes('pythos_founder'), 'Authoritatively granted Pythos Founder; derivedBadges reflects programId');

        // Grant LANZAR ID Founder
        const grant2 = await founderService.grantFounderDesignation({
            uid: testUid,
            programId: 'lanzar_id_founder',
            founderNumber: 7,
            title: 'LANZAR ID Pioneer',
            grantReason: 'System genesis founder',
            grantedBy: 'admin_test_operator'
        });
        assert(grant2.derivedBadges.length === 2, 'Authoritatively granted LANZAR ID Founder; derivedBadges now contains 2 badges');

        // Verify Anti-Tampering: Profile update cannot modify derivedBadges
        await profileService.updateUserProfile(testUid, {
            displayName: 'Commander Alexander',
            bio: 'Chief Systems Pilot',
            derivedBadges: ['hacked_badge_attempt'] // Tampering attempt
        });

        const profileAfterTamper = await profileService.getUserProfile(testUid);
        assert(profileAfterTamper.displayName === 'Commander Alexander', 'Valid profile display name updated');
        assert(!profileAfterTamper.derivedBadges.includes('hacked_badge_attempt'), 'Derived badges anti-tampering: unauthorized badge injected by PUT was stripped');
        assert(profileAfterTamper.derivedBadges.length === 2, 'Legitimate authoritative badges preserved intact');

        // Revoke Pythos Founder
        const revokeResult = await founderService.revokeFounderDesignation({
            uid: testUid,
            programId: 'pythos_founder',
            revocationReason: 'Consolidated into primary license',
            revokedBy: 'admin_test_operator'
        });
        assert(revokeResult.success === true && !revokeResult.derivedBadges.includes('pythos_founder'), 'Authoritatively revoked Pythos Founder; derivedBadges recomputed automatically to remove it');

        // -------------------------------------------------------------
        // SUITE 5: Audit Log Integrity & Sensitive Data Masking
        // -------------------------------------------------------------
        console.log('\n[SUITE 5] Audit Logging & Sensitive Data Masking');

        const sanitized = sanitizeAuditDetails({
            username: 'alex',
            password: 'SuperSecretPassword123',
            totpSecret: 'JBSWY3DPEHPK3PXP',
            clientId: 'portal'
        });
        assert(sanitized.password === '[REDACTED]', 'Sensitive password masked in audit details');
        assert(sanitized.totpSecret === '[REDACTED]', 'Sensitive totpSecret masked in audit details');
        assert(sanitized.clientId === 'portal', 'Non-sensitive audit details preserved');

        // Clean up test documents in Firestore
        console.log('\n[CLEANUP] Cleaning up test records from Firestore...');
        await profileService.eraseUserAccount(testUid, 'test_cleanup');
        console.log('  ✓ Cleaned up test cadet records.');

        console.log('\n================================================================');
        console.log(`  PHASE 2 QUALITY GATE SUMMARY: ${passCount} PASSED, ${failCount} FAILED`);
        console.log('================================================================\n');

        if (failCount > 0) {
            process.exit(1);
        } else {
            process.exit(0);
        }
    } catch (err) {
        console.error('FATAL TEST ERROR:', err);
        process.exit(1);
    }
}

runPhase2Tests();
