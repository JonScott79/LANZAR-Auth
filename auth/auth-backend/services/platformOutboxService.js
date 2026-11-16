// platformOutboxService.js
// Durable Transactional Outbox, Lease/Fencing Worker, Bounded Retries,
// Dead-Lettering, and Audited Redrive for Cross-Service Platform Admin Operations.

const crypto = require('crypto');

const DEFAULT_LEASE_DURATION_MS = 30000;
const DEFAULT_MAX_ATTEMPTS = 5;
const DEFAULT_BASE_BACKOFF_MS = 1000;
const DEFAULT_MAX_BACKOFF_MS = 60000;
const DEFAULT_POLL_INTERVAL_MS = 5000;

class PlatformOutboxService {
  constructor(db, authAdmin, options = {}) {
    if (!db || typeof db.collection !== 'function') {
      throw new Error('PlatformOutboxService requires a valid Firestore instance.');
    }
    this.db = db;
    this.authAdmin = authAdmin || null;
    this.auditLogService = options.auditLogService || null;
    this.workerId = options.workerId || `worker_${crypto.randomUUID()}`;
    this.leaseDurationMs = Number.isFinite(options.leaseDurationMs) ? options.leaseDurationMs : DEFAULT_LEASE_DURATION_MS;
    this.maxAttempts = Number.isInteger(options.maxAttempts) && options.maxAttempts > 0 ? options.maxAttempts : DEFAULT_MAX_ATTEMPTS;
    this.baseBackoffMs = Number.isFinite(options.baseBackoffMs) ? options.baseBackoffMs : DEFAULT_BASE_BACKOFF_MS;
    this.maxBackoffMs = Number.isFinite(options.maxBackoffMs) ? options.maxBackoffMs : DEFAULT_MAX_BACKOFF_MS;
    this.pollIntervalMs = Number.isFinite(options.pollIntervalMs) ? options.pollIntervalMs : DEFAULT_POLL_INTERVAL_MS;
    this._timer = null;
    this._running = false;
  }

  _computeBackoffMs(attempts) {
    const exp = Math.max(0, Number(attempts || 1) - 1);
    return Math.min(this.maxBackoffMs, this.baseBackoffMs * Math.pow(2, exp));
  }

  _evaluateDimensionVersion(event, userData) {
    const isRevoke = event && event.operation === 'platform.user.sessions_revoke_all';
    const eventVer = isRevoke ? event.revocationVersion : event.operationVersion;
    const latestVer = userData
      ? (isRevoke ? userData.desiredRevocationVersion : userData.desiredAuthVersion)
      : undefined;
    return {
      dimension: isRevoke ? 'revocation' : 'account',
      eventVer,
      latestVer,
      hasValidEventVer: Number.isInteger(eventVer) && eventVer >= 1,
      hasValidLatest: Number.isInteger(latestVer) && latestVer >= 1
    };
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
   * Atomically claims a transactional lease with a monotonically increasing fencing token.
   * Recovers events whose prior worker lease has expired (`leaseExpiresAt <= nowMs`).
   */
  async claimLease(outboxId, { workerId = this.workerId, nowMs = Date.now(), leaseDurationMs = this.leaseDurationMs, ignoreBackoff = false } = {}) {
    if (!outboxId) throw new Error('outboxId is required to claim lease.');
    const outboxRef = this.db.collection('security_outbox').doc(outboxId);

    return this.db.runTransaction(async (tx) => {
      const snap = await tx.get(outboxRef);
      if (!snap.exists) {
        return { claimed: false, reason: 'NOT_FOUND' };
      }
      const event = snap.data();

      if (event.status === 'COMPLETED') {
        return { claimed: false, reason: 'ALREADY_COMPLETED', event };
      }
      if (event.status === 'SUPERSEDED') {
        return { claimed: false, reason: 'SUPERSEDED', event };
      }
      if (event.status === 'DEAD_LETTER') {
        return { claimed: false, reason: 'DEAD_LETTER', event };
      }
      if (event.status === 'IN_PROGRESS' && Number(event.leaseExpiresAt || 0) > nowMs) {
        return { claimed: false, reason: 'LEASE_HELD', leaseOwner: event.leaseOwner, leaseExpiresAt: event.leaseExpiresAt };
      }
      if (!ignoreBackoff && event.status === 'FAILED_RETRYABLE' && Number(event.nextRetryAt || 0) > nowMs) {
        return { claimed: false, reason: 'BACKOFF_ACTIVE', nextRetryAt: event.nextRetryAt };
      }

      // Strict per-user, per-dimension causal ordering invariant:
      // - Account ops: desiredAuthVersion === event.operationVersion
      // - Revocation ops: desiredRevocationVersion === event.revocationVersion
      if (event.targetUid) {
        const userSnap = await tx.get(this.db.collection('users').doc(event.targetUid));
        const userData = userSnap.exists ? userSnap.data() : null;
        const { eventVer, latestVer, hasValidEventVer, hasValidLatest } = this._evaluateDimensionVersion(event, userData);

        if (!hasValidEventVer || !hasValidLatest || latestVer < eventVer) {
          const nowIso = new Date(nowMs).toISOString();
          const reasonCode = !hasValidEventVer ? 'MISSING_EVENT_VERSION' : (!hasValidLatest ? 'MISSING_DESIRED_VERSION' : 'VERSION_MISMATCH');
          tx.update(outboxRef, {
            status: 'DEAD_LETTER',
            lastErrorCode: reasonCode,
            deadLetteredAt: nowIso,
            leaseOwner: null,
            leaseExpiresAt: 0,
            updatedAt: nowIso
          });
          if (this.auditLogService && typeof this.auditLogService.buildAdminAuditRecord === 'function') {
            const prepared = this.auditLogService.buildAdminAuditRecord({
              auditId: `aud_outbox_${outboxId}_version_mismatch`,
              actorUid: event.actorUid || 'system_outbox_worker',
              actorEmail: null,
              actorTenantId: 'lanzar',
              actorRole: 'platform_admin',
              targetTenantId: 'lanzar',
              clientId: event.targetUid || null,
              operation: 'platform.outbox.version_mismatch',
              outcome: 'failure',
              correlationId: event.correlationId || null,
              metadata: {
                outboxId,
                targetUid: event.targetUid || null,
                eventVersion: eventVer ?? null,
                desiredVersion: latestVer ?? null,
                reasonCode
              }
            });
            this.auditLogService.writeInTransaction(tx, prepared);
          }
          return {
            claimed: false,
            reason: reasonCode,
            deadLetter: true,
            operationVersion: eventVer ?? null,
            desiredAuthVersion: latestVer ?? null
          };
        }

        if (latestVer > eventVer) {
          const nowIso = new Date(nowMs).toISOString();
          const idempotencyRef = event.idempotencyDocId
            ? this.db.collection('admin_idempotency').doc(event.idempotencyDocId)
            : null;
          const idempotencySnap = idempotencyRef ? await tx.get(idempotencyRef) : null;

          tx.update(outboxRef, {
            status: 'SUPERSEDED',
            supersededByVersion: latestVer,
            supersededAt: nowIso,
            leaseOwner: null,
            leaseExpiresAt: 0,
            updatedAt: nowIso
          });
          if (idempotencyRef && idempotencySnap && idempotencySnap.exists) {
            tx.update(idempotencyRef, {
              status: 'SUPERSEDED',
              externalAuthStatus: 'superseded',
              updatedAt: nowIso
            });
          }
          if (this.auditLogService && typeof this.auditLogService.buildAdminAuditRecord === 'function') {
            const prepared = this.auditLogService.buildAdminAuditRecord({
              auditId: `aud_outbox_${outboxId}_superseded_v${eventVer}`,
              actorUid: event.actorUid || 'system_outbox_worker',
              actorEmail: null,
              actorTenantId: 'lanzar',
              actorRole: 'platform_admin',
              targetTenantId: 'lanzar',
              clientId: event.targetUid || null,
              operation: 'platform.outbox.superseded',
              outcome: 'superseded',
              correlationId: event.correlationId || null,
              metadata: {
                outboxId,
                targetUid: event.targetUid || null,
                operationVersion: eventVer,
                supersededByVersion: latestVer,
                originalOperation: event.operation
              }
            });
            this.auditLogService.writeInTransaction(tx, prepared);
          }
          return {
            claimed: false,
            reason: 'SUPERSEDED',
            operationVersion: eventVer,
            supersededByVersion: latestVer
          };
        }
      }

      const nextFencingToken = Number(event.fencingToken || 0) + 1;
      const nowIso = new Date(nowMs).toISOString();
      const updatedFields = {
        status: 'IN_PROGRESS',
        leaseOwner: workerId,
        leaseExpiresAt: nowMs + leaseDurationMs,
        fencingToken: nextFencingToken,
        claimedAt: nowIso,
        updatedAt: nowIso
      };
      tx.update(outboxRef, updatedFields);

      return {
        claimed: true,
        fencingToken: nextFencingToken,
        workerId,
        event: { ...event, ...updatedFields }
      };
    });
  }

  /**
   * Persists completion or retry/dead-letter state ONLY if the caller still owns
   * the active lease and matching fencing token.
   */
  async _fencedPersist(outboxId, { workerId, fencingToken, nextStatus, patch = {}, auditOperation = null, auditOutcome = 'success', auditMetadata = {} }) {
    const outboxRef = this.db.collection('security_outbox').doc(outboxId);

    return this.db.runTransaction(async (tx) => {
      const snap = await tx.get(outboxRef);
      if (!snap.exists) {
        return { persisted: false, fenced: false, reason: 'NOT_FOUND' };
      }
      const current = snap.data();
      if (
        current.status !== 'IN_PROGRESS' ||
        current.leaseOwner !== workerId ||
        Number(current.fencingToken || 0) !== Number(fencingToken)
      ) {
        return {
          persisted: false,
          fenced: true,
          reason: 'STALE_FENCING_TOKEN',
          currentStatus: current.status,
          currentOwner: current.leaseOwner,
          currentFencingToken: current.fencingToken
        };
      }

      let idempotencySnap = null;
      const idempotencyRef = current.idempotencyDocId
        ? this.db.collection('admin_idempotency').doc(current.idempotencyDocId)
        : null;
      if (idempotencyRef) {
        idempotencySnap = await tx.get(idempotencyRef);
      }

      let effectiveStatus = nextStatus;
      let effectiveOutcome = auditOutcome;
      let effectiveOperation = auditOperation;
      let extraPatch = {};
      let userSnap = null;
      const userRef = current.targetUid ? this.db.collection('users').doc(current.targetUid) : null;
      if (userRef) {
        userSnap = await tx.get(userRef);
        const userData = userSnap.exists ? userSnap.data() : null;
        const { eventVer, latestVer, hasValidEventVer, hasValidLatest } = this._evaluateDimensionVersion(current, userData);
        if (!hasValidEventVer || !hasValidLatest || latestVer < eventVer) {
          effectiveStatus = 'DEAD_LETTER';
          effectiveOutcome = 'failure';
          effectiveOperation = 'platform.outbox.version_mismatch';
          extraPatch = { lastErrorCode: 'VERSION_MISMATCH', deadLetteredAt: new Date().toISOString() };
        } else if (latestVer > eventVer) {
          effectiveStatus = 'SUPERSEDED';
          effectiveOutcome = 'superseded';
          effectiveOperation = 'platform.outbox.superseded';
          extraPatch = { supersededByVersion: latestVer, supersededAt: new Date().toISOString() };
        }
      }

      const nowIso = new Date().toISOString();
      const finalPatch = {
        ...patch,
        ...extraPatch,
        status: effectiveStatus,
        leaseOwner: null,
        leaseExpiresAt: 0,
        updatedAt: nowIso
      };
      tx.update(outboxRef, finalPatch);

      if (userRef && userSnap && userSnap.exists && effectiveStatus === 'COMPLETED' && Number.isInteger(current.revocationVersion)) {
        const userData = userSnap.data();
        const curApplied = Number(userData.appliedRevocationVersion || 0);
        if (current.revocationVersion > curApplied) {
          const revUpdate = { appliedRevocationVersion: current.revocationVersion, updatedAt: nowIso };
          if (patch && patch.observedTokensValidAfterTime) {
            revUpdate.observedTokensValidAfterTime = patch.observedTokensValidAfterTime;
          }
          tx.update(userRef, revUpdate);
        }
      }

      if (idempotencyRef && idempotencySnap && idempotencySnap.exists) {
        const externalAuthStatus = effectiveStatus === 'COMPLETED'
          ? 'completed'
          : (effectiveStatus === 'SUPERSEDED'
            ? 'superseded'
            : (effectiveStatus === 'DEAD_LETTER' ? 'dead_letter' : 'pending'));
        tx.update(idempotencyRef, {
          status: effectiveStatus,
          externalAuthStatus,
          updatedAt: nowIso
        });
      }

      if (effectiveOperation && this.auditLogService && typeof this.auditLogService.buildAdminAuditRecord === 'function') {
        const auditId = `aud_outbox_${outboxId}_${effectiveStatus.toLowerCase()}_f${fencingToken}`;
        const prepared = this.auditLogService.buildAdminAuditRecord({
          auditId,
          actorUid: current.actorUid || 'system_outbox_worker',
          actorEmail: null,
          actorTenantId: 'lanzar',
          actorRole: 'platform_admin',
          targetTenantId: 'lanzar',
          clientId: current.targetUid || null,
          operation: effectiveOperation,
          outcome: effectiveOutcome,
          correlationId: current.correlationId || null,
          metadata: {
            outboxId,
            targetUid: current.targetUid || null,
            fencingToken,
            workerId,
            operationVersion: current.operationVersion || null,
            ...auditMetadata
          }
        });
        this.auditLogService.writeInTransaction(tx, prepared);
      }

      return { persisted: true, fenced: false, status: effectiveStatus };
    });
  }

  async _assertLeaseAndFreshness(event, { workerId, fencingToken }) {
    const outboxSnap = await this.db.collection('security_outbox').doc(event.outboxId).get();
    if (!outboxSnap.exists) {
      const err = new Error('OUTBOX_NOT_FOUND');
      err.code = 'outbox/fenced';
      throw err;
    }
    const cur = outboxSnap.data();
    if (cur.status !== 'IN_PROGRESS' || cur.leaseOwner !== workerId || Number(cur.fencingToken || 0) !== Number(fencingToken)) {
      const err = new Error('STALE_FENCING_TOKEN');
      err.code = 'outbox/fenced';
      throw err;
    }
    if (event.targetUid) {
      const userSnap = await this.db.collection('users').doc(event.targetUid).get();
      const userData = userSnap.exists ? userSnap.data() : null;
      const { eventVer, latestVer, hasValidEventVer, hasValidLatest } = this._evaluateDimensionVersion(event, userData);
      if (!hasValidEventVer || !hasValidLatest || latestVer < eventVer) {
        const err = new Error('VERSION_MISMATCH');
        err.code = 'outbox/version-mismatch';
        err.latestVersion = latestVer ?? null;
        throw err;
      }
      if (latestVer > eventVer) {
        const err = new Error('SUPERSEDED_BY_NEWER_OPERATION');
        err.code = 'outbox/superseded';
        err.latestVersion = latestVer;
        throw err;
      }
    }
  }

  /**
   * Executes the desired-state Firebase Auth convergence step with durable progress
   * markers and pre-call lease/version freshness checks.
   */
  async _executeExternalAuth(event, { authAdmin = this.authAdmin, workerId = this.workerId, fencingToken = event.fencingToken } = {}) {
    if (!authAdmin) {
      const err = new Error('AUTH_ADMIN_UNAVAILABLE');
      err.code = 'auth/service-unavailable';
      throw err;
    }

    const progress = { ...(event.progress || {}) };
    if (event.operation === 'platform.user.status_update') {
      if (!progress.updateUserDone) {
        await this._assertLeaseAndFreshness(event, { workerId, fencingToken });
        await authAdmin.updateUser(event.targetUid, {
          disabled: Boolean(event.payload && event.payload.disabled)
        });
        progress.updateUserDone = true;
      }
      if (event.payload && event.payload.revokeRefreshTokens) {
        if (!progress.revokeRefreshTokensDone) {
          await this._assertLeaseAndFreshness(event, { workerId, fencingToken });
          try {
            await authAdmin.revokeRefreshTokens(event.targetUid);
          } catch (err) {
            if (err.code !== 'auth/user-not-found') {
              err._partialProgress = progress;
              throw err;
            }
          }
          progress.revokeRefreshTokensDone = true;
        }
      } else {
        progress.revokeRefreshTokensDone = true;
      }
      return progress;
    }

    if (event.operation === 'platform.user.sessions_revoke_all') {
      if (!progress.revokeRefreshTokensDone) {
        await this._assertLeaseAndFreshness(event, { workerId, fencingToken });
        try {
          await authAdmin.revokeRefreshTokens(event.targetUid);
          if (typeof authAdmin.getUser === 'function') {
            const verifiedUser = await authAdmin.getUser(event.targetUid);
            if (!this._isRevocationVerified(verifiedUser, event.desiredRevokedAt)) {
              const verErr = new Error('REVOCATION_VERIFICATION_FAILED');
              verErr.code = 'auth/revocation-not-verified';
              throw verErr;
            }
            progress.observedTokensValidAfterTime = verifiedUser.tokensValidAfterTime;
          }
        } catch (err) {
          if (err.code !== 'auth/user-not-found') {
            err._partialProgress = progress;
            throw err;
          }
        }
        progress.revokeRefreshTokensDone = true;
      }
      return progress;
    }

    const err = new Error('UNSUPPORTED_OUTBOX_OPERATION');
    err.code = 'outbox/unsupported-operation';
    throw err;
  }

  /**
   * Claims, executes, and fences completion/retry/dead-letter for a single outbox event.
   */
  async processEventById(outboxId, { workerId = this.workerId, nowMs = Date.now(), authAdmin = this.authAdmin, ignoreBackoff = false } = {}) {
    const claim = await this.claimLease(outboxId, { workerId, nowMs, ignoreBackoff });
    if (!claim.claimed) {
      if (claim.reason === 'ALREADY_COMPLETED') {
        return { status: 'COMPLETED', outboxId, alreadyCompleted: true };
      }
      if (claim.reason === 'SUPERSEDED') {
        return { status: 'SUPERSEDED', outboxId, superseded: true, supersededByVersion: claim.supersededByVersion || null };
      }
      if (claim.reason === 'DEAD_LETTER' || claim.reason === 'MISSING_EVENT_VERSION' || claim.reason === 'MISSING_DESIRED_VERSION' || claim.reason === 'VERSION_MISMATCH') {
        return { status: 'DEAD_LETTER', outboxId, deadLetter: true, reason: claim.reason };
      }
      return { status: 'SKIPPED', outboxId, reason: claim.reason };
    }

    const { fencingToken, event } = claim;
    const nextAttempts = Number(event.attempts || 0) + 1;

    try {
      const finalProgress = await this._executeExternalAuth(event, { authAdmin, workerId, fencingToken });
      const nowIso = new Date().toISOString();
      const persistRes = await this._fencedPersist(outboxId, {
        workerId,
        fencingToken,
        nextStatus: 'COMPLETED',
        patch: {
          attempts: nextAttempts,
          progress: finalProgress,
          ...(finalProgress.observedTokensValidAfterTime ? { observedTokensValidAfterTime: finalProgress.observedTokensValidAfterTime } : {}),
          completedAt: nowIso
        },
        auditOperation: 'platform.outbox.completed',
        auditOutcome: 'success',
        auditMetadata: { attempts: nextAttempts, originalOperation: event.operation }
      });

      if (persistRes.fenced) {
        return { status: 'FENCED', outboxId, fencingToken };
      }
      return { status: persistRes.status || 'COMPLETED', outboxId, attempts: nextAttempts, fencingToken };
    } catch (err) {
      if (err && err.code === 'outbox/fenced') {
        return { status: 'FENCED', outboxId, fencingToken };
      }
      if (err && err.code === 'outbox/version-mismatch') {
        const vmRes = await this._fencedPersist(outboxId, {
          workerId,
          fencingToken,
          nextStatus: 'DEAD_LETTER',
          patch: { lastErrorCode: 'VERSION_MISMATCH', deadLetteredAt: new Date().toISOString() },
          auditOperation: 'platform.outbox.version_mismatch',
          auditOutcome: 'failure',
          auditMetadata: { operationVersion: event.operationVersion ?? null, desiredAuthVersion: err.latestVersion ?? null }
        });
        return vmRes.fenced ? { status: 'FENCED', outboxId, fencingToken } : { status: 'DEAD_LETTER', outboxId, deadLetter: true, reason: 'VERSION_MISMATCH' };
      }
      if (err && err.code === 'outbox/superseded') {
        const supRes = await this._fencedPersist(outboxId, {
          workerId,
          fencingToken,
          nextStatus: 'SUPERSEDED',
          patch: { supersededByVersion: err.latestVersion || null, supersededAt: new Date().toISOString() },
          auditOperation: 'platform.outbox.superseded',
          auditOutcome: 'superseded',
          auditMetadata: { operationVersion: event.operationVersion || null, supersededByVersion: err.latestVersion || null }
        });
        return supRes.fenced ? { status: 'FENCED', outboxId, fencingToken } : { status: 'SUPERSEDED', outboxId, superseded: true };
      }
      const partialProgress = err._partialProgress || event.progress || {};
      const errorCode = err.code || 'EXTERNAL_AUTH_ERROR';
      const nowIso = new Date().toISOString();
      const isDeadLetter = nextAttempts >= this.maxAttempts;
      const nextStatus = isDeadLetter ? 'DEAD_LETTER' : 'FAILED_RETRYABLE';
      const backoffMs = isDeadLetter ? 0 : this._computeBackoffMs(nextAttempts);

      const patch = {
        attempts: nextAttempts,
        progress: partialProgress,
        lastErrorCode: String(errorCode).slice(0, 64),
        lastErrorAt: nowIso
      };
      if (isDeadLetter) {
        patch.deadLetteredAt = nowIso;
      } else {
        patch.nextRetryAt = nowMs + backoffMs;
      }

      const persistRes = await this._fencedPersist(outboxId, {
        workerId,
        fencingToken,
        nextStatus,
        patch,
        auditOperation: isDeadLetter ? 'platform.outbox.dead_lettered' : null,
        auditOutcome: 'failure',
        auditMetadata: { attempts: nextAttempts, errorCode, originalOperation: event.operation }
      });

      if (persistRes.fenced) {
        return { status: 'FENCED', outboxId, fencingToken };
      }
      return {
        status: nextStatus,
        outboxId,
        attempts: nextAttempts,
        errorCode,
        nextRetryAt: patch.nextRetryAt || null
      };
    }
  }

  /**
   * Sweeps eligible pending, retryable, or expired-lease outbox events.
   */
  async runOnce({ nowMs = Date.now(), limit = 25 } = {}) {
    const snap = await this.db.collection('security_outbox')
      .where('type', '==', 'platform_admin_cross_service')
      .limit(limit * 2)
      .get();

    const results = [];
    for (const doc of snap.docs) {
      if (results.length >= limit) break;
      const d = doc.data();
      const eligible =
        d.status === 'PENDING_EXTERNAL_AUTH' ||
        (d.status === 'FAILED_RETRYABLE' && Number(d.nextRetryAt || 0) <= nowMs) ||
        (d.status === 'IN_PROGRESS' && Number(d.leaseExpiresAt || 0) <= nowMs);
      if (!eligible) continue;

      const res = await this.processEventById(doc.id, { nowMs });
      results.push(res);
    }
    return results;
  }

  /**
   * Audited administrative redrive for DEAD_LETTER or FAILED_RETRYABLE outbox events.
   */
  async redriveEvent({ outboxId, actorUid, actorEmail = null, actorTenantId = 'lanzar', correlationId = null, executeImmediately = true } = {}) {
    if (!outboxId || !actorUid) {
      throw new Error('outboxId and actorUid are required for administrative redrive.');
    }
    if (!this.auditLogService || typeof this.auditLogService.buildAdminAuditRecord !== 'function') {
      throw new Error('AUDIT_SERVICE_UNAVAILABLE');
    }

    const outboxRef = this.db.collection('security_outbox').doc(outboxId);
    const auditId = `aud_${crypto.randomUUID()}`;
    const nowIso = new Date().toISOString();

    await this.db.runTransaction(async (tx) => {
      const snap = await tx.get(outboxRef);
      if (!snap.exists) {
        throw new Error('OUTBOX_EVENT_NOT_FOUND');
      }
      const event = snap.data();
      if (event.status === 'COMPLETED') {
        throw new Error('OUTBOX_ALREADY_COMPLETED');
      }
      if (event.status === 'SUPERSEDED') {
        throw new Error('OUTBOX_SUPERSEDED');
      }
      if (event.status === 'IN_PROGRESS' && Number(event.leaseExpiresAt || 0) > Date.now()) {
        throw new Error('OUTBOX_LEASE_ACTIVE');
      }

      const idempotencyRef = event.idempotencyDocId
        ? this.db.collection('admin_idempotency').doc(event.idempotencyDocId)
        : null;
      const idempotencySnap = idempotencyRef ? await tx.get(idempotencyRef) : null;

      tx.update(outboxRef, {
        status: 'PENDING_EXTERNAL_AUTH',
        attempts: 0,
        nextRetryAt: 0,
        leaseOwner: null,
        leaseExpiresAt: 0,
        redrivenAt: nowIso,
        redrivenBy: actorUid,
        updatedAt: nowIso
      });

      if (idempotencyRef && idempotencySnap && idempotencySnap.exists) {
        tx.update(idempotencyRef, {
          status: 'PENDING_EXTERNAL_AUTH',
          externalAuthStatus: 'pending',
          updatedAt: nowIso
        });
      }

      const preparedAudit = this.auditLogService.buildAdminAuditRecord({
        auditId,
        actorUid,
        actorEmail,
        actorTenantId,
        actorRole: 'platform_admin',
        targetTenantId: 'lanzar',
        clientId: event.targetUid || null,
        operation: 'platform.outbox.redrive',
        outcome: 'success',
        correlationId,
        metadata: {
          outboxId,
          targetUid: event.targetUid || null,
          previousStatus: event.status,
          originalOperation: event.operation
        }
      });
      this.auditLogService.writeInTransaction(tx, preparedAudit);
    });

    if (executeImmediately) {
      const processResult = await this.processEventById(outboxId);
      return { redriven: true, outboxId, auditId, processResult };
    }
    return { redriven: true, outboxId, auditId };
  }

  start() {
    if (this._running) return;
    this._running = true;
    const tick = async () => {
      if (!this._running) return;
      try {
        await this.runOnce();
      } catch (err) {
        console.error('[OUTBOX WORKER ERROR]', err.message);
      }
      if (this._running) {
        this._timer = setTimeout(tick, this.pollIntervalMs);
      }
    };
    this._timer = setTimeout(tick, this.pollIntervalMs);
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
  PlatformOutboxService,
  DEFAULT_LEASE_DURATION_MS,
  DEFAULT_MAX_ATTEMPTS,
  DEFAULT_BASE_BACKOFF_MS,
  DEFAULT_MAX_BACKOFF_MS,
  DEFAULT_POLL_INTERVAL_MS
};
