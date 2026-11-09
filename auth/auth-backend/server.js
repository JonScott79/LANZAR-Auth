require('dotenv').config();
const { initializeApp, cert, getApps } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const { getFirestore } = require('firebase-admin/firestore');
const { createApp } = require('./app');
const { getEnvConfig } = require('./config/environments');

// ==========================================
// Firebase Admin Initialization
// PRESERVE FINDING 2 (Production credential fallback - pending separate authorized remediation)
// ==========================================
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

const firebaseApp = getApps().length > 0 ? getApps()[0] : initializeApp({ credential: credentialConfig });
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
