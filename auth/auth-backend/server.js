require('dotenv').config();
const { initializeApp, cert, getApps } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const { getFirestore } = require('firebase-admin/firestore');
const { createApp } = require('./app');
const { getEnvConfig } = require('./config/environments');

const fs = require('fs');

// ==========================================
// Firebase Admin Initialization (Fail-Closed)
// Remediation for Finding B: Production credential fallback eliminated.
// Requires explicit environment configuration or emulator host.
// ==========================================
let credentialConfig = null;
const isEmulator = Boolean(process.env.FIRESTORE_EMULATOR_HOST || process.env.FIREBASE_AUTH_EMULATOR_HOST);
const projectId = process.env.FIREBASE_PROJECT_ID || process.env.PROJECT_ID;

if (process.env.FIREBASE_SERVICE_ACCOUNT_KEY) {
    try {
        const serviceAccountParams = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY);
        credentialConfig = cert(serviceAccountParams);
    } catch (err) {
        console.error('❌ [FATAL] Failed to parse FIREBASE_SERVICE_ACCOUNT_KEY from environment');
        process.exit(1);
    }
} else if (process.env.FIREBASE_CREDENTIAL_PATH) {
    try {
        if (!fs.existsSync(process.env.FIREBASE_CREDENTIAL_PATH)) {
            console.error(`❌ [FATAL] Specified FIREBASE_CREDENTIAL_PATH does not exist: ${process.env.FIREBASE_CREDENTIAL_PATH}`);
            process.exit(1);
        }
        const serviceAccount = JSON.parse(fs.readFileSync(process.env.FIREBASE_CREDENTIAL_PATH, 'utf8'));
        credentialConfig = cert(serviceAccount);
    } catch (err) {
        console.error(`❌ [FATAL] Failed to load credential from FIREBASE_CREDENTIAL_PATH: ${err.message}`);
        process.exit(1);
    }
} else if (isEmulator) {
    console.log('[FIREBASE INIT] Running in offline emulator mode without live credentials.');
} else {
    console.error('❌ [FATAL] Missing Firebase credentials in non-emulator environment.');
    console.error('   Set FIREBASE_SERVICE_ACCOUNT_KEY or FIREBASE_CREDENTIAL_PATH explicitly.');
    console.error('   Production credential fallback has been permanently removed.');
    process.exit(1);
}

const firebaseAppOptions = {};
if (credentialConfig) {
    firebaseAppOptions.credential = credentialConfig;
}
if (projectId) {
    firebaseAppOptions.projectId = projectId;
}

const firebaseApp = getApps().length > 0 ? getApps()[0] : initializeApp(firebaseAppOptions);
const db = getFirestore(firebaseApp);
const authAdmin = getAuth(firebaseApp);

let config = null;
try {
    const appEnv = process.env.APP_ENV || (process.env.NODE_ENV === 'production' ? 'production' : 'development');
    config = getEnvConfig(appEnv);
} catch (e) {
    // Development fallback
}

// Instantiate Modular Express Application via Shared Factory
const {
    app,
    sessionService,
    founderService,
    profileService,
    smsService
} = createApp({
    config,
    db,
    authAdmin
});

const PORT = process.env.PORT || 4001;
app.listen(PORT, () => {
    console.log(`[LANZAR ID AUTH-BACKEND] Operations Center API listening on port ${PORT}`);
});

module.exports = { app, sessionService, founderService, profileService, smsService };
