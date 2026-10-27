require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { initializeApp, cert } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');
const crypto = require('crypto');
const { AuthorizationCodeStore } = require('./store');
const { getClient } = require('./clients');
const {
    generateBase32Secret,
    generateTOTP,
    verifyTOTP,
    generateRecoveryCodes,
    verifyAndConsumeRecoveryCode,
    createMfaSignedToken,
    verifyMfaSignedToken
} = require('./mfaService');

let credentialConfig;
if (process.env.FIREBASE_SERVICE_ACCOUNT_KEY) {
  try {
    const serviceAccountParams = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY);
    credentialConfig = cert(serviceAccountParams);
  } catch (err) {
    console.error('Failed to parse FIREBASE_SERVICE_ACCOUNT_KEY from environment');
    process.exit(1);
  }
} else {
  try {
    const serviceAccount = require('../../firebase-credentials/lanzar-95ae3-firebase-adminsdk-fbsvc-86e8ea5817.json');
    credentialConfig = cert(serviceAccount);
  } catch (err) {
    console.warn('No local service account file found, and no FIREBASE_SERVICE_ACCOUNT_KEY provided.');
  }
}

initializeApp({
  credential: credentialConfig
});

const db = getFirestore();
const authAdmin = getAuth();

const app = express();
app.use(cors());
app.use(express.json());

const codeStore = new AuthorizationCodeStore();

/**
 * Checks whether a user has administrative privileges.
 */
async function isUserAdmin(uid, email) {
    if (!uid && !email) return false;
    try {
        if (uid) {
            const adminDoc = await db.collection('admins').doc(uid).get();
            if (adminDoc.exists && adminDoc.data().active === true) {
                return true;
            }
        }
        if (email) {
            const emailQuery = await db.collection('admins')
                .where('email', '==', email.toLowerCase())
                .where('active', '==', true)
                .limit(1)
                .get();
            if (!emailQuery.empty) {
                return true;
            }
        }
        return false;
    } catch (e) {
        console.error('[AUTH ADMIN CHECK ERROR]', e.message);
        return false;
    }
}

/**
 * Reconciles or provisions a canonical customer profile in Firestore upon registration or OAuth sign-in.
 */
async function reconcileCustomerAccount({ uid, email, displayName, businessName, dispatchOptIn }) {
    if (!uid || !email) return;
    const normalizedEmail = email.trim().toLowerCase();
    const customerRef = db.collection('customers').doc(uid);
    const userRef = db.collection('users').doc(uid);

    const [custSnap, userSnap] = await Promise.all([
        customerRef.get(),
        userRef.get()
    ]);

    const resolvedName = displayName || (custSnap.exists && custSnap.data().customerName) || normalizedEmail.split('@')[0];

    // If customer record doesn't exist, create it with baseline permissions
    if (!custSnap.exists) {
        console.log(`[PROVISION] Initializing new customer profile for ${uid} (${normalizedEmail})`);
        await customerRef.set({
            id: uid,
            customerId: uid,
            customerName: resolvedName,
            customerEmail: normalizedEmail,
            authEmail: normalizedEmail,
            businessName: businessName || '',
            role: 'customer',
            active: true,
            services: ['portal', 'tickets'],
            createdAt: FieldValue.serverTimestamp(),
            updatedAt: FieldValue.serverTimestamp()
        });
    }

    // Ensure users/{uid} is synchronized
    if (!userSnap.exists) {
        console.log(`[PROVISION] Synchronizing users collection document for ${uid}`);
        await userRef.set({
            displayName: resolvedName,
            email: normalizedEmail,
            role: 'customer',
            active: true,
            services: ['portal', 'tickets'],
            createdAt: FieldValue.serverTimestamp(),
            updatedAt: FieldValue.serverTimestamp()
        });
    }

    // Handle newsletter opt-in consent if requested
    if (dispatchOptIn === true) {
        const subscriberRef = db.collection('mailing_list').doc(normalizedEmail);
        const subSnap = await subscriberRef.get();
        
        // Do not silently reactivate unsubscribed addresses
        if (subSnap.exists && subSnap.data().status === 'unsubscribed') {
            console.log(`[DISPATCH] Subscriber ${normalizedEmail} previously unsubscribed. Suppression preserved.`);
        } else {
            console.log(`[DISPATCH] Recording explicit newsletter consent for ${normalizedEmail}`);
            await subscriberRef.set({
                email: normalizedEmail,
                fullName: resolvedName,
                status: 'active',
                source: 'lanzar-id',
                consentVersion: 'dispatch_v1',
                consentText: 'Send me The LANZAR Dispatch — news, project updates, new services, and occasional offers.',
                consentedAt: FieldValue.serverTimestamp(),
                updatedAt: FieldValue.serverTimestamp()
            }, { merge: true });
        }
    }
}

// =====================================
// Account Registration & Provisioning
// =====================================

app.post('/register', async (req, res) => {
    try {
        const { email, password, fullName, businessName, dispatchOptIn } = req.body;
        if (!email || !password || !fullName) {
            return res.status(400).json({ error: 'invalid_request', error_description: 'Name, email, and password are required.' });
        }
        if (password.length < 8) {
            return res.status(400).json({ error: 'weak_password', error_description: 'Password must be at least 8 characters.' });
        }

        const normalizedEmail = email.trim().toLowerCase();

        // 1. Create Firebase Auth user
        let userRecord;
        try {
            userRecord = await authAdmin.createUser({
                email: normalizedEmail,
                password,
                displayName: fullName.trim()
            });
        } catch (authErr) {
            if (authErr.code === 'auth/email-already-exists') {
                return res.status(409).json({ error: 'email_exists', error_description: 'An account with this email address already exists.' });
            }
            throw authErr;
        }

        // 2. Server-controlled provisioning
        await reconcileCustomerAccount({
            uid: userRecord.uid,
            email: normalizedEmail,
            displayName: fullName.trim(),
            businessName: businessName?.trim() || '',
            dispatchOptIn: Boolean(dispatchOptIn)
        });

        console.log(`[REGISTER] Successfully registered and provisioned customer ${userRecord.uid} (${normalizedEmail})`);
        return res.json({
            success: true,
            uid: userRecord.uid,
            email: normalizedEmail
        });
    } catch (err) {
        console.error('[REGISTER ERROR]', err);
        return res.status(500).json({ error: 'server_error', error_description: 'Failed to create account: ' + err.message });
    }
});

// Explicit provisioning endpoint for client-authenticated users (e.g. Google OAuth first login)
app.post('/provision', async (req, res) => {
    try {
        const { idToken, fullName, businessName, dispatchOptIn } = req.body;
        if (!idToken) {
            return res.status(400).json({ error: 'invalid_request', error_description: 'Missing idToken.' });
        }

        const decoded = await authAdmin.verifyIdToken(idToken);
        await reconcileCustomerAccount({
            uid: decoded.uid,
            email: decoded.email,
            displayName: fullName || decoded.name,
            businessName: businessName || '',
            dispatchOptIn: Boolean(dispatchOptIn)
        });

        return res.json({ success: true, uid: decoded.uid });
    } catch (err) {
        console.error('[PROVISION ERROR]', err);
        return res.status(401).json({ error: 'invalid_token', error_description: 'Failed to verify token: ' + err.message });
    }
});

// =====================================
// MFA Endpoints
// =====================================

app.post('/mfa/status', async (req, res) => {
    try {
        const { idToken } = req.body;
        if (!idToken) return res.status(400).json({ error: 'missing_token' });
        const decoded = await authAdmin.verifyIdToken(idToken);
        const isAdmin = await isUserAdmin(decoded.uid, decoded.email);

        const mfaDoc = await db.collection('mfa_factors').doc(decoded.uid).get();
        const mfaData = mfaDoc.exists ? mfaDoc.data() : null;
        const isEnrolled = Boolean(mfaData && mfaData.enabled);

        return res.json({
            uid: decoded.uid,
            isAdmin,
            mfaRequired: isAdmin,
            mfaEnrolled: isEnrolled,
            factors: mfaData ? { totp: Boolean(mfaData.totpSecret) } : { totp: false }
        });
    } catch (err) {
        return res.status(401).json({ error: 'invalid_token', error_description: err.message });
    }
});

app.post('/mfa/totp/setup', async (req, res) => {
    try {
        const { idToken } = req.body;
        if (!idToken) return res.status(400).json({ error: 'missing_token' });
        const decoded = await authAdmin.verifyIdToken(idToken);

        const secret = generateBase32Secret(20);
        const issuer = 'LANZAR ID';
        const otpauthUrl = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(decoded.email)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;

        return res.json({
            success: true,
            secret,
            otpauthUrl
        });
    } catch (err) {
        return res.status(401).json({ error: 'invalid_token', error_description: err.message });
    }
});

app.post('/mfa/totp/enable', async (req, res) => {
    try {
        const { idToken, secret, code } = req.body;
        if (!idToken || !secret || !code) {
            return res.status(400).json({ error: 'missing_parameters' });
        }
        const decoded = await authAdmin.verifyIdToken(idToken);

        const isValid = verifyTOTP(secret, code);
        if (!isValid) {
            return res.status(400).json({ error: 'invalid_code', error_description: 'Verification code incorrect. Please try again.' });
        }

        const { plainCodes, hashedRecords } = generateRecoveryCodes(8);

        await db.collection('mfa_factors').doc(decoded.uid).set({
            uid: decoded.uid,
            email: decoded.email,
            enabled: true,
            totpSecret: secret,
            recoveryCodes: hashedRecords,
            enrolledAt: FieldValue.serverTimestamp(),
            updatedAt: FieldValue.serverTimestamp()
        }, { merge: true });

        console.log(`[MFA] Successfully enabled TOTP MFA for ${decoded.uid} (${decoded.email})`);
        return res.json({
            success: true,
            recoveryCodes: plainCodes
        });
    } catch (err) {
        return res.status(500).json({ error: 'server_error', error_description: err.message });
    }
});

app.post('/mfa/verify', async (req, res) => {
    try {
        const { mfaSession, code, method } = req.body;
        if (!mfaSession || !code) {
            return res.status(400).json({ error: 'missing_parameters' });
        }

        const sessionPayload = verifyMfaSignedToken(mfaSession);
        if (!sessionPayload || sessionPayload.action !== 'mfa_challenge') {
            return res.status(401).json({ error: 'session_expired', error_description: 'MFA session has expired. Please sign in again.' });
        }

        const uid = sessionPayload.uid;
        const mfaDoc = await db.collection('mfa_factors').doc(uid).get();
        if (!mfaDoc.exists || !mfaDoc.data().enabled) {
            return res.status(400).json({ error: 'mfa_not_enrolled', error_description: 'MFA is not enrolled for this account.' });
        }

        const mfaData = mfaDoc.data();
        let verified = false;

        if (method === 'recovery') {
            const recoveryResult = verifyAndConsumeRecoveryCode(code, mfaData.recoveryCodes || []);
            if (recoveryResult.valid) {
                verified = true;
                await db.collection('mfa_factors').doc(uid).update({
                    recoveryCodes: recoveryResult.updatedRecords,
                    updatedAt: FieldValue.serverTimestamp()
                });
                console.log(`[MFA] Consumed recovery code for user ${uid}`);
            }
        } else {
            // Default to TOTP
            verified = verifyTOTP(mfaData.totpSecret, code);
        }

        if (!verified) {
            return res.status(401).json({ error: 'invalid_code', error_description: 'The code provided is invalid or expired.' });
        }

        // Generate verified proof token (valid for 5 minutes)
        const mfaProof = createMfaSignedToken({
            uid,
            email: sessionPayload.email,
            action: 'mfa_verified',
            verifiedAt: Date.now()
        }, 300000);

        console.log(`[MFA] Verification successful for ${uid}`);
        return res.json({
            success: true,
            mfaProof
        });
    } catch (err) {
        console.error('[MFA VERIFY ERROR]', err);
        return res.status(500).json({ error: 'server_error', error_description: err.message });
    }
});

// =====================================
// OAuth2 / PKCE Authorization Endpoints
// =====================================

app.post('/authorize', async (req, res) => {
    try {
        const { idToken, client_id, redirect_uri, state, code_challenge, code_challenge_method, mfa_proof } = req.body;
        console.log(`[AUTH] Received authorize request for client: ${client_id}`);

        if (!idToken || !client_id || !redirect_uri || !state || !code_challenge || code_challenge_method !== 'S256') {
            return res.status(400).json({ error: 'invalid_request', error_description: 'Missing or invalid parameters' });
        }

        const client = getClient(client_id);
        if (!client || !client.enabled) {
            return res.status(400).json({ error: 'invalid_client', error_description: 'Unknown or disabled client' });
        }

        const normalizedRedirect = redirect_uri.replace(/\/+$/, '');
        const isAuthorized = client.redirectUris.some(uri => {
            const clean = uri.replace(/\/+$/, '');
            return clean === normalizedRedirect || normalizedRedirect.startsWith(clean + '/');
        });
        if (!isAuthorized) {
            console.warn(`[AUTH] Unauthorized redirect URI attempt for ${client_id}: ${redirect_uri}`);
            return res.status(400).json({ error: 'invalid_request', error_description: 'Unauthorized redirect URI' });
        }

        let decodedToken;
        try {
            decodedToken = await authAdmin.verifyIdToken(idToken);
        } catch (e) {
            console.error('[AUTH] Invalid ID token:', e.message);
            return res.status(401).json({ error: 'invalid_grant', error_description: 'Invalid user token' });
        }
        const uid = decodedToken.uid;
        const email = decodedToken.email;

        // Auto-reconcile customer record so new users are never stranded with ACCESS DENIED
        await reconcileCustomerAccount({
            uid,
            email,
            displayName: decodedToken.name,
            businessName: '',
            dispatchOptIn: false
        });

        // Check Admin & MFA status
        const isAdmin = await isUserAdmin(uid, email);
        const mfaDoc = await db.collection('mfa_factors').doc(uid).get();
        const hasMfa = mfaDoc.exists && mfaDoc.data().enabled;

        // Admin accounts strictly require MFA
        if (isAdmin || hasMfa) {
            let mfaVerified = false;
            if (mfa_proof) {
                const proofPayload = verifyMfaSignedToken(mfa_proof);
                if (proofPayload && proofPayload.uid === uid && proofPayload.action === 'mfa_verified') {
                    mfaVerified = true;
                }
            }

            if (!mfaVerified) {
                const mfaSession = createMfaSignedToken({
                    uid,
                    email,
                    action: 'mfa_challenge',
                    isAdmin
                }, 600000); // 10 minutes session

                return res.status(403).json({
                    error: 'mfa_required',
                    error_description: isAdmin && !hasMfa ? 'Administrator accounts require MFA enrollment.' : 'Multi-Factor Authentication required.',
                    mfa_required: true,
                    enrollment_required: isAdmin && !hasMfa,
                    mfa_session: mfaSession,
                    methods: hasMfa ? ['totp', 'recovery'] : ['totp']
                });
            }
        }

        const code = await codeStore.createCode({
            uid,
            clientId: client_id,
            redirectUri: redirect_uri,
            codeChallenge: code_challenge,
            mfaVerified: isAdmin || hasMfa
        });

        console.log(`[AUTH] Generated authorization code for ${uid} -> ${client_id}`);
        res.json({ code, state });
    } catch (error) {
        console.error('[AUTH] Server error during authorize:', error);
        res.status(500).json({ error: 'server_error' });
    }
});

app.post('/exchange', async (req, res) => {
    try {
        const { code, client_id, redirect_uri, code_verifier } = req.body;
        console.log(`[EXCHANGE] Received exchange request for client: ${client_id}`);

        if (!code || !client_id || !redirect_uri || !code_verifier) {
            return res.status(400).json({ error: 'invalid_request' });
        }

        const record = await codeStore.getCode(code);
        if (!record) {
            console.warn('[EXCHANGE] Code not found');
            return res.status(400).json({ error: 'invalid_grant' });
        }
        if (record.used) {
            console.warn(`[EXCHANGE] Attempt to reuse authorization code by ${client_id}`);
            return res.status(400).json({ error: 'invalid_grant' });
        }
        if (Date.now() > record.expiresAt) {
            console.warn(`[EXCHANGE] Expired code used by ${client_id}`);
            return res.status(400).json({ error: 'invalid_grant' });
        }
        const reqRedirect = redirect_uri.replace(/\/+$/, '');
        const recRedirect = record.redirectUri.replace(/\/+$/, '');
        if (record.clientId !== client_id || reqRedirect !== recRedirect) {
            console.warn('[EXCHANGE] Client ID or Redirect URI mismatch:', { recordClient: record.clientId, client_id, recRedirect, reqRedirect });
            return res.status(400).json({ error: 'invalid_grant' });
        }

        const hash = crypto.createHash('sha256').update(code_verifier).digest('base64url');
        if (hash !== record.codeChallenge) {
            console.warn('[EXCHANGE] PKCE code_challenge mismatch');
            return res.status(400).json({ error: 'invalid_grant' });
        }

        // Security assertion: Check admin MFA requirement during token creation
        const isAdmin = await isUserAdmin(record.uid);
        if (isAdmin && !record.mfaVerified) {
            console.warn(`[SECURITY] Blocked exchange for admin ${record.uid} lacking verified MFA.`);
            return res.status(401).json({ error: 'unauthorized', error_description: 'Administrator MFA verification required.' });
        }

        await codeStore.markUsed(code);

        const customToken = await authAdmin.createCustomToken(record.uid);
        console.log(`[EXCHANGE] Successfully issued custom token for ${record.uid} -> ${client_id}`);
        res.json({ custom_token: customToken });
    } catch (error) {
        console.error('[EXCHANGE] Server error during exchange:', error);
        res.status(500).json({ error: 'server_error' });
    }
});

const PORT = process.env.PORT || 4001;
app.listen(PORT, () => {
    console.log(`[AUTH-BACKEND] Listening on port ${PORT}`);
});
