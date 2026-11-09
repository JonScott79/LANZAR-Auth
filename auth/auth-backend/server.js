require('dotenv').config();
const { initializeApp, cert, getApps } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const { getFirestore } = require('firebase-admin/firestore');
const { createApp } = require('./app');
const { ENV_CONFIGS } = require('./config/environments');
const { isLoopbackEndpoint } = require('./config/bootstrap');

const fs = require('fs');

// ==========================================
// Firebase Admin Initialization (Fail-Closed)
// Remediation for Finding B: Production credential fallback eliminated.
// Requires explicit environment configuration or emulator host.
// ==========================================
const hasFirestoreEmu = Boolean(process.env.FIRESTORE_EMULATOR_HOST);
const hasAuthEmu = Boolean(process.env.FIREBASE_AUTH_EMULATOR_HOST);

// 1. Partial emulator configuration rejection:
// Require all emulator endpoints used by the application to be explicitly configured.
if (hasFirestoreEmu !== hasAuthEmu) {
    console.error('❌ [FATAL] Partial emulator configuration detected.');
    console.error('   Both FIRESTORE_EMULATOR_HOST and FIREBASE_AUTH_EMULATOR_HOST must be explicitly configured, or neither.');
    console.error(`   FIRESTORE_EMULATOR_HOST: ${process.env.FIRESTORE_EMULATOR_HOST || '(unset)'}`);
    console.error(`   FIREBASE_AUTH_EMULATOR_HOST: ${process.env.FIREBASE_AUTH_EMULATOR_HOST || '(unset)'}`);
    console.error('   Refusing startup to prevent partial fallback to live services or ADC.');
    process.exit(1);
}

const isEmulator = hasFirestoreEmu && hasAuthEmu;

// 2. Loopback endpoint verification:
if (isEmulator) {
    if (!isLoopbackEndpoint(process.env.FIRESTORE_EMULATOR_HOST)) {
        console.error(`❌ [FATAL] FIRESTORE_EMULATOR_HOST must be a local loopback endpoint (127.0.0.1 or localhost), got "${process.env.FIRESTORE_EMULATOR_HOST}"`);
        process.exit(1);
    }
    if (!isLoopbackEndpoint(process.env.FIREBASE_AUTH_EMULATOR_HOST)) {
        console.error(`❌ [FATAL] FIREBASE_AUTH_EMULATOR_HOST must be a local loopback endpoint (127.0.0.1 or localhost), got "${process.env.FIREBASE_AUTH_EMULATOR_HOST}"`);
        process.exit(1);
    }
}

let credentialConfig = null;
let serviceAccountObj = null;
const projectId = process.env.FIREBASE_PROJECT_ID || process.env.PROJECT_ID;

if (process.env.FIREBASE_SERVICE_ACCOUNT_KEY) {
    try {
        serviceAccountObj = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY);
    } catch (err) {
        console.error(`❌ [FATAL] Failed to parse FIREBASE_SERVICE_ACCOUNT_KEY from environment: ${err.message}`);
        process.exit(1);
    }
} else if (process.env.FIREBASE_CREDENTIAL_PATH) {
    try {
        if (!fs.existsSync(process.env.FIREBASE_CREDENTIAL_PATH)) {
            console.error(`❌ [FATAL] Specified FIREBASE_CREDENTIAL_PATH does not exist: ${process.env.FIREBASE_CREDENTIAL_PATH}`);
            process.exit(1);
        }
        serviceAccountObj = JSON.parse(fs.readFileSync(process.env.FIREBASE_CREDENTIAL_PATH, 'utf8'));
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

// 3. Project ID and Environment Validation:
if (isEmulator) {
    if (!projectId) {
        console.error('❌ [FATAL] In emulator mode, FIREBASE_PROJECT_ID is required to prevent accidental default fallback.');
        process.exit(1);
    }
}

if (serviceAccountObj) {
    if (projectId && serviceAccountObj.project_id && projectId !== serviceAccountObj.project_id) {
        console.error(`❌ [FATAL] Project ID mismatch: environment (${projectId}) does not match service account (${serviceAccountObj.project_id})`);
        process.exit(1);
    }
}

const appEnv = process.env.APP_ENV;
if (appEnv && ENV_CONFIGS && ENV_CONFIGS[appEnv]) {
    const spec = ENV_CONFIGS[appEnv];
    const resolvedProjectId = projectId || (serviceAccountObj && serviceAccountObj.project_id);
    if (resolvedProjectId && spec.projectId && resolvedProjectId !== spec.projectId) {
        console.error(`❌ [FATAL] Project ID mismatch: resolved project "${resolvedProjectId}" does not match required "${spec.projectId}" for APP_ENV=${appEnv}`);
        process.exit(1);
    }
    if (spec.emulators === 'forbidden' && isEmulator) {
        console.error(`❌ [FATAL] Emulators are forbidden in APP_ENV=${appEnv}`);
        process.exit(1);
    }
    if (spec.emulators === 'required' && !isEmulator) {
        console.error(`❌ [FATAL] Emulators are required in APP_ENV=${appEnv}`);
        process.exit(1);
    }
}

if (serviceAccountObj) {
    try {
        credentialConfig = cert(serviceAccountObj);
    } catch (err) {
        console.error(`❌ [FATAL] Failed to initialize credentials from service account: ${err.message}`);
        process.exit(1);
    }
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
    const activeEnv = appEnv || (process.env.NODE_ENV === 'production' ? 'production' : 'development');
    config = (ENV_CONFIGS && ENV_CONFIGS[activeEnv]) || null;
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
