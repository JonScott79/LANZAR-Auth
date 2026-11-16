// desiredStateReconciler.js
// Periodic Authoritative Desired-State Reconciler for Firebase Authentication.
// Independently detects and repairs drift for BOTH:
//   1. Account disabled state (`desiredAuthVersion` / `desiredAuthDisabled` vs `authUser.disabled`)
//   2. Refresh-token revocation (`desiredRevocationVersion` / `desiredRevokedAt` vs `appliedRevocationVersion` & `authUser.tokensValidAfterTime`)

const crypto = require('crypto');

const DEFAULT_LEASE_DURATION_MS = 30000;
const DEFAULT_RECONCILE_INTERVAL_MS = 60000;
const DEFAULT_MAX_ATTEMPTS = 5;
const DEFAULT_BASE_BACKOFF_MS = 2000;
const DEFAULT_MAX_BACKOFF_MS = 60000;
const DEFAULT_SWEEP_POLL_MS = 15000;

class DesiredStateReconciler {
  constructor(db, authAdmin, options = {}) {
    if (!db || typeof db.collection !== 'function') {
      throw new Error('DesiredStateReconciler requires a valid Firestore instance.');
    }
    this.db = db;
    this.authAdmin = authAdmin || null;
    this.auditLogService = options.auditLogService || null;
    this.workerId = options.workerId || `reconciler_${crypto.randomUUID()}`;
    this.leaseDurationMs = Number.isFinite(options.leaseDurationMs) ? options.leaseDurationMs : DEFAULT_LEASE_DURATION_MS;
    this.reconcileIntervalMs = Number.isFinite(options.reconcileIntervalMs) ? options.reconcileIntervalMs : DEFAULT_RECONCILE_INTERVAL_MS;
    this.maxAttempts = Number.isInteger(options.maxAttempts) && options.maxAttempts > 0 ? options.maxAttempts : DEFAULT_MAX_ATTEMPTS;
    this.baseBackoffMs = Number.isFinite(options.baseBackoffMs) ? options.baseBackoffMs : DEFAULT_BASE_BACKOFF_MS;
    this.maxBackoffMs = Number.isFinite(options.maxBackoffMs) ? options.maxBackoffMs : DEFAULT_MAX_BACKOFF_MS;
    this.sweepPollMs = Number.isFinite(options.sweepPollMs) ? options.sweepPollMs : DEFAULT_SWEEP_POLL_MS;
    this._timer = null;
    this._running = false;
  }

  _computeBackoffMs(attempts) {
    const exp = Math.max(0, Number(attempts || 1) - 1);
    return Math.min(this.maxBackoffMs, this.baseBackoffMs * Math.pow(2, exp));
  }

  _isRevocationVerified(authUser, desiredRevokedAt) {
    if (!authUser || !authUser.tokensValidAfterTime) return false;
    const obsMs = Date.parse(authUser.tokensValidAfterTime);
    if (!Number.isFinite(obsMs)) return false;
    if (!desiredRevokedAt) return true;
    const desMs = Date.parse(desiredRevokedAt);
    if (!Number.isFinite(desMs)) return true;
    // Firebase Auth tokensValidAfterTime has 1-second resolution (truncated to whole seconds).
    return Math.floor(obsMs / 1000) >= Math.floor(desMs / 1000);
  }

  /**
   * Atomically claims a reconciliation lease on `/auth_reconciliation/{uid}`.
   */
  async claimReconciliationLease(uid, { workerId = this.workerId, nowMs = Date.now(), ignoreSchedule = false } = {}) {
    if (!uid) throw new Error('uid is required to claim reconciliation lease.');
    const userRef = this.db.collection('users').doc(uid);
    const recRef = this.db.collection('auth_reconciliation').doc(uid);

    return this.db.runTransaction(async (tx) => {
      const [userSnap, recSnap] = await Promise.all([tx.get(userRef), tx.get(recRef)]);
      if (!userSnap.exists) {
        return { claimed: false, reason: 'USER_NOT_FOUND' };
      }
      const userData = userSnap.data();
      const hasAccountState = Number.isInteger(userData.desiredAuthVersion) && userData.desiredAuthVersion >= 1 && typeof userData.desiredAuthDisabled === 'boolean';
      const hasRevocationState = Number.isInteger(userData.desiredRevocationVersion) && userData.desiredRevocationVersion >= 1;
      if (!hasAccountState && !hasRevocationState) {
        return { claimed: false, reason: 'NO_DESIRED_AUTH_STATE' };
      }

      const rec = recSnap.exists ? recSnap.data() : {};
      if (rec.status === 'DEAD_LETTER') {
        return { claimed: false, reason: 'DEAD_LETTER' };
      }
      if (rec.status === 'IN_PROGRESS' && Number(rec.leaseExpiresAt || 0) > nowMs) {
        return { claimed: false, reason: 'LEASE_HELD', leaseOwner: rec.leaseOwner };
      }
      if (!ignoreSchedule && rec.status === 'DRIFT_RETRYABLE' && Number(rec.nextCheckAt || 0) > nowMs) {
        return { claimed: false, reason: 'BACKOFF_ACTIVE', nextCheckAt: rec.nextCheckAt };
      }

      const accountUpToDate = !hasAccountState || Number(rec.lastMatchedVersion || 0) === userData.desiredAuthVersion;
      const revocationUpToDate = !hasRevocationState || Number(userData.appliedRevocationVersion || 0) >= userData.desiredRevocationVersion;
      if (!ignoreSchedule && rec.status === 'CONVERGED' && Number(rec.nextCheckAt || 0) > nowMs && accountUpToDate && revocationUpToDate) {
        return { claimed: false, reason: 'INTERVAL_NOT_ELAPSED', nextCheckAt: rec.nextCheckAt };
      }

      const nextFencingToken = Number(rec.fencingToken || 0) + 1;
      const nowIso = new Date(nowMs).toISOString();
      const leaseDoc = {
        uid,
        status: 'IN_PROGRESS',
        leaseOwner: workerId,
        leaseExpiresAt: nowMs + this.leaseDurationMs,
        fencingToken: nextFencingToken,
        attempts: Number(rec.attempts || 0),
        lastMatchedVersion: Number(rec.lastMatchedVersion || 0),
        lastMatchedRevocationVersion: Number(rec.lastMatchedRevocationVersion || 0),
        claimedAt: nowIso,
        updatedAt: nowIso
      };
      if (recSnap.exists) {
        tx.update(recRef, leaseDoc);
      } else {
        tx.set(recRef, { ...leaseDoc, createdAt: nowIso });
      }

      return {
        claimed: true,
        fencingToken: nextFencingToken,
        workerId,
        attempts: Number(rec.attempts || 0),
        desiredAuthVersion: hasAccountState ? userData.desiredAuthVersion : 0,
        desiredAuthDisabled: hasAccountState ? userData.desiredAuthDisabled : null,
        desiredRevocationVersion: hasRevocationState ? userData.desiredRevocationVersion : 0,
        desiredRevokedAt: userData.desiredRevokedAt || null,
        appliedRevocationVersion: Number(userData.appliedRevocationVersion || 0)
      };
    });
  }

  /**
   * Fenced update on `/auth_reconciliation/{uid}` (and optional `/users/{uid}` revocation progress)
   * ensuring only the current lease owner with the matching fencing token can persist results.
   */
  async _fencedComplete(uid, { workerId, fencingToken, nextStatus, patch = {}, userRevocationUpdate = null, auditOperation = null, auditOutcome = 'success', auditMetadata = {}, nowMs = Date.now() }) {
    const recRef = this.db.collection('auth_reconciliation').doc(uid);
    const userRef = this.db.collection('users').doc(uid);

    return this.db.runTransaction(async (tx) => {
      const snap = await tx.get(recRef);
      if (!snap.exists) {
        return { persisted: false, fenced: true, reason: 'NOT_FOUND' };
      }
      const cur = snap.data();
      if (cur.status !== 'IN_PROGRESS' || cur.leaseOwner !== workerId || Number(cur.fencingToken || 0) !== Number(fencingToken)) {
        return { persisted: false, fenced: true, reason: 'STALE_FENCING_TOKEN' };
      }

      let userSnap = null;
      if (userRevocationUpdate) {
        userSnap = await tx.get(userRef);
      }

      const nowIso = new Date(nowMs).toISOString();
      tx.update(recRef, {
        ...patch,
        status: nextStatus,
        leaseOwner: null,
        leaseExpiresAt: 0,
        updatedAt: nowIso
      });

      if (userRevocationUpdate && userSnap && userSnap.exists) {
        const curApplied = Number(userSnap.data().appliedRevocationVersion || 0);
        if (userRevocationUpdate.appliedRevocationVersion > curApplied) {
          tx.update(userRef, {
            appliedRevocationVersion: userRevocationUpdate.appliedRevocationVersion,
            observedTokensValidAfterTime: userRevocationUpdate.observedTokensValidAfterTime,
            updatedAt: nowIso
          });
        }
      }

      if (auditOperation && this.auditLogService && typeof this.auditLogService.buildAdminAuditRecord === 'function') {
        const versionTag = auditMetadata.desiredAuthVersion || auditMetadata.desiredRevocationVersion || 0;
        const auditId = `aud_reconcile_${uid}_v${versionTag}_f${fencingToken}_${nextStatus.toLowerCase()}`;
        const prepared = this.auditLogService.buildAdminAuditRecord({
          auditId,
          actorUid: 'system_desired_state_reconciler',
          actorEmail: null,
          actorTenantId: 'lanzar',
          actorRole: 'platform_admin',
          targetTenantId: 'lanzar',
          clientId: uid,
          operation: auditOperation,
          outcome: auditOutcome,
          correlationId: null,
          metadata: {
            uid,
            workerId,
            fencingToken,
            ...auditMetadata
          }
        });
        this.auditLogService.writeInTransaction(tx, prepared);
      }

      return { persisted: true, fenced: false, status: nextStatus };
    });
  }

  /**
   * Compares `/users/{uid}` desired account state and desired revocation state
   * against Firebase Auth, repairs any drift, and verifies the resulting state.
   */
  async reconcileUser(uid, { workerId = this.workerId, nowMs = Date.now(), authAdmin = this.authAdmin, ignoreSchedule = false } = {}) {
    const claim = await this.claimReconciliationLease(uid, { workerId, nowMs, ignoreSchedule });
    if (!claim.claimed) {
      return { status: 'SKIPPED', uid, reason: claim.reason };
    }

    const { fencingToken } = claim;
    const nextAttempts = claim.attempts + 1;

    try {
      if (!authAdmin || typeof authAdmin.getUser !== 'function') {
        const err = new Error('AUTH_ADMIN_UNAVAILABLE');
        err.code = 'auth/service-unavailable';
        throw err;
      }

      let authUser;
      try {
        authUser = await authAdmin.getUser(uid);
      } catch (err) {
        if (err && err.code === 'auth/user-not-found') {
          const res = await this._fencedComplete(uid, {
            workerId,
            fencingToken,
            nextStatus: 'CONVERGED',
            nowMs,
            patch: {
              attempts: 0,
              lastMatchedVersion: claim.desiredAuthVersion,
              lastMatchedRevocationVersion: claim.desiredRevocationVersion,
              lastCheckedAt: new Date(nowMs).toISOString(),
              nextCheckAt: nowMs + this.reconcileIntervalMs
            }
          });
          return res.fenced ? { status: 'FENCED', uid } : { status: 'CONVERGED', uid, userNotFound: true };
        }
        throw err;
      }

      // Re-read authoritative desired state right before comparing/repairing
      const latestUserSnap = await this.db.collection('users').doc(uid).get();
      const latestData = latestUserSnap.exists ? latestUserSnap.data() : {};
      const latestVersion = Number.isInteger(latestData.desiredAuthVersion) ? latestData.desiredAuthVersion : claim.desiredAuthVersion;
      const latestDisabled = typeof latestData.desiredAuthDisabled === 'boolean' ? latestData.desiredAuthDisabled : claim.desiredAuthDisabled;
      const latestRevVersion = Number.isInteger(latestData.desiredRevocationVersion) ? latestData.desiredRevocationVersion : claim.desiredRevocationVersion;
      const latestRevokedAt = latestData.desiredRevokedAt || claim.desiredRevokedAt || null;
      const appliedRevVersion = Number(latestData.appliedRevocationVersion || 0);

      const hasAccountState = latestVersion >= 1 && typeof latestDisabled === 'boolean';
      const observedDisabled = Boolean(authUser && authUser.disabled);
      const accountDrift = hasAccountState && (observedDisabled !== latestDisabled);

      const hasRevocationState = latestRevVersion >= 1;
      const timestampValid = this._isRevocationVerified(authUser, latestRevokedAt);
      const revocationOutstanding = hasRevocationState && ((appliedRevVersion < latestRevVersion) || !timestampValid);

      if (!accountDrift && !revocationOutstanding) {
        const res = await this._fencedComplete(uid, {
          workerId,
          fencingToken,
          nextStatus: 'CONVERGED',
          nowMs,
          patch: {
            attempts: 0,
            lastMatchedVersion: latestVersion,
            lastMatchedRevocationVersion: latestRevVersion,
            lastCheckedAt: new Date(nowMs).toISOString(),
            nextCheckAt: nowMs + this.reconcileIntervalMs
          }
        });
        return res.fenced ? { status: 'FENCED', uid } : { status: 'CONVERGED', uid, driftDetected: false, version: latestVersion, revocationVersion: latestRevVersion };
      }

      // Verify lease is still held before mutating Firebase Auth
      const preWriteRec = (await this.db.collection('auth_reconciliation').doc(uid).get()).data();
      if (!preWriteRec || preWriteRec.status !== 'IN_PROGRESS' || preWriteRec.leaseOwner !== workerId || Number(preWriteRec.fencingToken) !== Number(fencingToken)) {
        return { status: 'FENCED', uid };
      }

      if (accountDrift) {
        await authAdmin.updateUser(uid, { disabled: latestDisabled });
      }

      let userRevocationUpdate = null;
      let revocationRepaired = false;
      if (revocationOutstanding) {
        if (!timestampValid) {
          await authAdmin.revokeRefreshTokens(uid);
          const verifiedUser = await authAdmin.getUser(uid);
          if (!this._isRevocationVerified(verifiedUser, latestRevokedAt)) {
            const verErr = new Error('REVOCATION_VERIFICATION_FAILED');
            verErr.code = 'auth/revocation-not-verified';
            throw verErr;
          }
          userRevocationUpdate = {
            appliedRevocationVersion: latestRevVersion,
            observedTokensValidAfterTime: verifiedUser.tokensValidAfterTime
          };
          revocationRepaired = true;
        } else {
          // Firebase Auth tokensValidAfterTime already satisfies the desired cutoff (e.g. applied via outbox)
          userRevocationUpdate = {
            appliedRevocationVersion: latestRevVersion,
            observedTokensValidAfterTime: authUser.tokensValidAfterTime
          };
        }
      }

      const nowIso = new Date(nowMs).toISOString();
      const auditOperation = accountDrift
        ? 'platform.reconciliation.drift_repaired'
        : (revocationRepaired ? 'platform.reconciliation.revocation_repaired' : null);

      const persistRes = await this._fencedComplete(uid, {
        workerId,
        fencingToken,
        nextStatus: 'CONVERGED',
        nowMs,
        patch: {
          attempts: 0,
          lastMatchedVersion: latestVersion,
          lastMatchedRevocationVersion: latestRevVersion,
          lastCheckedAt: nowIso,
          lastRepairedAt: nowIso,
          nextCheckAt: nowMs + this.reconcileIntervalMs
        },
        userRevocationUpdate,
        auditOperation,
        auditOutcome: 'success',
        auditMetadata: {
          desiredAuthVersion: latestVersion,
          desiredRevocationVersion: latestRevVersion,
          accountDrift,
          revocationRepaired,
          observedDisabled,
          repairedDisabled: latestDisabled
        }
      });

      if (persistRes.fenced) {
        return { status: 'FENCED', uid };
      }
      const repairedSomething = accountDrift || revocationRepaired;
      return {
        status: repairedSomething ? 'REPAIRED' : 'CONVERGED',
        uid,
        driftDetected: repairedSomething,
        accountDrift,
        revocationRepaired,
        version: latestVersion,
        revocationVersion: latestRevVersion,
        observedDisabled,
        repairedDisabled: latestDisabled
      };
    } catch (err) {
      const errorCode = (err && err.code) ? String(err.code).slice(0, 64) : 'RECONCILIATION_ERROR';
      const nowIso = new Date(nowMs).toISOString();
      const isDeadLetter = nextAttempts >= this.maxAttempts;
      const nextStatus = isDeadLetter ? 'DEAD_LETTER' : 'DRIFT_RETRYABLE';
      const backoffMs = isDeadLetter ? 0 : this._computeBackoffMs(nextAttempts);

      const patch = {
        attempts: nextAttempts,
        lastErrorCode: errorCode,
        lastErrorAt: nowIso
      };
      if (isDeadLetter) {
        patch.deadLetteredAt = nowIso;
      } else {
        patch.nextCheckAt = nowMs + backoffMs;
      }

      const failRes = await this._fencedComplete(uid, {
        workerId,
        fencingToken,
        nextStatus,
        nowMs,
        patch,
        auditOperation: isDeadLetter ? 'platform.reconciliation.dead_lettered' : null,
        auditOutcome: 'failure',
        auditMetadata: {
          desiredAuthVersion: claim.desiredAuthVersion,
          desiredRevocationVersion: claim.desiredRevocationVersion,
          attempts: nextAttempts,
          errorCode
        }
      });

      if (failRes.fenced) {
        return { status: 'FENCED', uid };
      }
      return { status: nextStatus, uid, attempts: nextAttempts, errorCode };
    }
  }

  /**
   * Sweeps users with `desiredAuthVersion >= 1` or `desiredRevocationVersion >= 1`.
   */
  async runOnce({ nowMs = Date.now(), limit = 25, ignoreSchedule = false } = {}) {
    const [authSnap, revSnap] = await Promise.all([
      this.db.collection('users').where('desiredAuthVersion', '>=', 1).limit(limit).get(),
      this.db.collection('users').where('desiredRevocationVersion', '>=', 1).limit(limit).get()
    ]);

    const uids = new Set();
    authSnap.forEach(doc => uids.add(doc.id));
    revSnap.forEach(doc => uids.add(doc.id));

    const results = [];
    for (const uid of uids) {
      if (results.length >= limit) break;
      const res = await this.reconcileUser(uid, { nowMs, ignoreSchedule });
      if (res.status !== 'SKIPPED') {
        results.push(res);
      }
    }
    return results;
  }

  /**
   * Audited operator redrive for DEAD_LETTER or DRIFT_RETRYABLE reconciliation records.
   */
  async redriveUser({ uid, actorUid, actorEmail = null, actorTenantId = 'lanzar', correlationId = null, executeImmediately = true } = {}) {
    if (!uid || !actorUid) {
      throw new Error('uid and actorUid are required for reconciliation redrive.');
    }
    if (!this.auditLogService || typeof this.auditLogService.buildAdminAuditRecord !== 'function') {
      throw new Error('AUDIT_SERVICE_UNAVAILABLE');
    }

    const recRef = this.db.collection('auth_reconciliation').doc(uid);
    const auditId = `aud_${crypto.randomUUID()}`;
    const nowIso = new Date().toISOString();

    await this.db.runTransaction(async (tx) => {
      const snap = await tx.get(recRef);
      if (!snap.exists) {
        throw new Error('RECONCILIATION_NOT_FOUND');
      }
      const cur = snap.data();
      if (cur.status === 'IN_PROGRESS' && Number(cur.leaseExpiresAt || 0) > Date.now()) {
        throw new Error('RECONCILIATION_LEASE_ACTIVE');
      }

      tx.update(recRef, {
        status: 'IDLE',
        attempts: 0,
        nextCheckAt: 0,
        leaseOwner: null,
        leaseExpiresAt: 0,
        redrivenAt: nowIso,
        redrivenBy: actorUid,
        updatedAt: nowIso
      });

      const preparedAudit = this.auditLogService.buildAdminAuditRecord({
        auditId,
        actorUid,
        actorEmail,
        actorTenantId,
        actorRole: 'platform_admin',
        targetTenantId: 'lanzar',
        clientId: uid,
        operation: 'platform.reconciliation.redrive',
        outcome: 'success',
        correlationId,
        metadata: { uid, previousStatus: cur.status }
      });
      this.auditLogService.writeInTransaction(tx, preparedAudit);
    });

    if (executeImmediately) {
      const reconcileResult = await this.reconcileUser(uid, { ignoreSchedule: true });
      return { redriven: true, uid, auditId, reconcileResult };
    }
    return { redriven: true, uid, auditId };
  }

  start() {
    if (this._running) return;
    this._running = true;
    const tick = async () => {
      if (!this._running) return;
      try {
        await this.runOnce();
      } catch (err) {
        console.error('[DESIRED STATE RECONCILER ERROR]', err.message);
      }
      if (this._running) {
        this._timer = setTimeout(tick, this.sweepPollMs);
      }
    };
    this._timer = setTimeout(tick, this.sweepPollMs);
  }

  stop() {
    this._running = false;
    if (this._timer) {
      clearTimeout(this._timer);
      this._timer = null;
    }
  }
}

module.exports = {
  DesiredStateReconciler,
  DEFAULT_LEASE_DURATION_MS,
  DEFAULT_RECONCILE_INTERVAL_MS,
  DEFAULT_MAX_ATTEMPTS,
  DEFAULT_BASE_BACKOFF_MS,
  DEFAULT_MAX_BACKOFF_MS,
  DEFAULT_SWEEP_POLL_MS
};
