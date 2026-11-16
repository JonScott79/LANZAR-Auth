// worker.js
// LANZAR ID Persistent Platform Outbox Worker
// Designed to run as a separate Railway worker service sharing the same
// Firestore and Firebase Admin project configuration as server.js.

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
const { bootstrap } = require('./config/bootstrap');
const { validateReceiptKeyConfiguration } = require('./store');
const { validateSigningKeyEncryptionConfiguration } = require('./services/signingKeystore');
const { AuditLogService } = require('./services/auditLogService');
const { PlatformOutboxService } = require('./services/platformOutboxService');
const { DesiredStateReconciler } = require('./services/desiredStateReconciler');

let config;
try {
    config = bootstrap(process.env);
    validateReceiptKeyConfiguration(process.env);
    validateSigningKeyEncryptionConfiguration(process.env);
} catch (err) {
    console.error(`❌ [WORKER FATAL] ${err.message}`);
    process.exit(1);
}

const hasAuthEmu = Boolean(process.env.FIREBASE_AUTH_EMULATOR_HOST);
const hasFirestoreEmu = Boolean(process.env.FIRESTORE_EMULATOR_HOST);
const isEmulator = hasAuthEmu && hasFirestoreEmu;

const firebaseAppOptions = { projectId: config.projectId };
if (config.serviceAccount) {
    firebaseAppOptions.credential = cert(config.serviceAccount);
} else if (isEmulator) {
    console.log('[OUTBOX WORKER] Running in offline emulator mode without live credentials.');
}

const firebaseApp = getApps().length > 0 ? getApps()[0] : initializeApp(firebaseAppOptions);
const db = getFirestore(firebaseApp);
const authAdmin = getAuth(firebaseApp);
const auditLogService = new AuditLogService(db);

const pollIntervalMs = Number(process.env.OUTBOX_WORKER_POLL_MS || 5000);
const leaseDurationMs = Number(process.env.OUTBOX_LEASE_DURATION_MS || 30000);
const maxAttempts = Number(process.env.OUTBOX_MAX_ATTEMPTS || 5);

const reconcileIntervalMs = Number(process.env.RECONCILE_INTERVAL_MS || 60000);
const reconcileSweepPollMs = Number(process.env.RECONCILE_SWEEP_POLL_MS || 15000);

const outboxService = new PlatformOutboxService(db, authAdmin, {
    auditLogService,
    pollIntervalMs,
    leaseDurationMs,
    maxAttempts
});

const reconciler = new DesiredStateReconciler(db, authAdmin, {
    auditLogService,
    leaseDurationMs,
    reconcileIntervalMs,
    sweepPollMs: reconcileSweepPollMs,
    maxAttempts
});

console.log(`🚀 LANZAR ID Outbox & Desired-State Worker started (outboxWorker=${outboxService.workerId}, reconciler=${reconciler.workerId})`);
outboxService.start();
reconciler.start();

function shutdown(signal) {
    console.log(`[OUTBOX WORKER] Received ${signal}, stopping gracefully...`);
    outboxService.stop();
    reconciler.stop();
    process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
