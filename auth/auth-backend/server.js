// server.js
// LANZAR ID Operations Center API Server
// Hardened Fail-Closed Startup Validation (LID-VER-004, LID-VER-005)

const path = require('path');
require('dotenv').config({
    path: [
        path.resolve(__dirname, '.env'),
        path.resolve(__dirname, '../.env'),
        path.resolve(process.cwd(), '.env')
    ]
});

const { initializeApp, cert, getApps } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const { getFirestore } = require('firebase-admin/firestore');
const { createApp } = require('./app');
const { bootstrap } = require('./config/bootstrap');

// =========================================================================
// Fail-Closed Startup Validation (LID-VER-004 & LID-VER-005)
// Execute comprehensive bootstrap validation BEFORE opening network ports.
// If any required configuration is missing, weak, or invalid, abort with code 1.
// =========================================================================
let config;
try {
    config = bootstrap(process.env);
} catch (err) {
    console.error(`❌ [FATAL] ${err.message}`);
    process.exit(1);
}

// =========================================================================
// Firebase Admin Initialization (Guaranteed Validated Config)
// =========================================================================
const hasAuthEmu = Boolean(process.env.FIREBASE_AUTH_EMULATOR_HOST);
const hasFirestoreEmu = Boolean(process.env.FIRESTORE_EMULATOR_HOST);
const isEmulator = hasAuthEmu && hasFirestoreEmu;

const firebaseAppOptions = {
    projectId: config.projectId
};

if (config.serviceAccount) {
    try {
        firebaseAppOptions.credential = cert(config.serviceAccount);
    } catch (err) {
        console.error(`❌ [FATAL] Failed to initialize credentials from service account: ${err.message}`);
        process.exit(1);
    }
} else if (isEmulator) {
    console.log('[FIREBASE INIT] Running in offline emulator mode without live credentials.');
}

const firebaseApp = getApps().length > 0 ? getApps()[0] : initializeApp(firebaseAppOptions);
const db = getFirestore(firebaseApp);
const authAdmin = getAuth(firebaseApp);

// =========================================================================
// Instantiate Modular Express Application via Shared Factory
// =========================================================================
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
const HOST = process.env.HOST || '::';
const server = app.listen(PORT, HOST, () => {
    console.log(`[LANZAR ID AUTH-BACKEND] Operations Center API listening on port ${PORT} (${HOST})`);
});

module.exports = { app, server, sessionService, founderService, profileService, smsService };
