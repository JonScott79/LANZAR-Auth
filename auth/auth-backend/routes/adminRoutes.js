// adminRoutes.js
// Administrative endpoints (Portal Mission Control) for LANZAR ID

const crypto = require('crypto');
const express = require('express');
const { FieldValue } = require('firebase-admin/firestore');
const { clients } = require('../clients');
const { PlatformOutboxService } = require('../services/platformOutboxService');
const { computeTtlDate, ADMIN_IDEMPOTENCY_TTL_GRACE_MS } = require('../services/ttlHelper');

const IDEMPOTENCY_KEY_REGEX = /^[A-Za-z0-9._:-]{16,128}$/;
const IDEMPOTENCY_TTL_MS = 24 * 60 * 60 * 1000;

/**
 * Validates and derives a scoped Firestore idempotency document ID + canonical request hash.
 */
function parseAndScopeIdempotencyKey(req, { actorUid, actorTenantId, operation, targetUid, canonicalPayload }) {
  const rawKey = typeof req.get === 'function'
    ? (req.get('Idempotency-Key') || req.get('idempotency-key'))
    : (req.headers && (req.headers['idempotency-key'] || req.headers['Idempotency-Key']));
  const key = typeof rawKey === 'string' ? rawKey.trim() : '';
  if (!key || !IDEMPOTENCY_KEY_REGEX.test(key)) {
    return {
      valid: false,
      error: 'Idempotency-Key header is required and must be 16-128 characters matching [A-Za-z0-9._:-].'
    };
  }
  const scopeString = `${actorUid}:${actorTenantId}:${operation}:${targetUid}:${key}`;
  const idempotencyDocId = `idem_${crypto.createHash('sha256').update(scopeString).digest('hex')}`;
  const requestHash = crypto.createHash('sha256').update(JSON.stringify(canonicalPayload || {})).digest('hex');
  return { valid: true, key, idempotencyDocId, requestHash };
}

/**
 * Backwards-compatible wrapper that reconciles a single outbox event via PlatformOutboxService.
 */
async function reconcilePlatformOutboxEvent({ db, authAdmin, auditLogService = null, outboxId }) {
  const svc = new PlatformOutboxService(db, authAdmin, { auditLogService });
  return svc.processEventById(outboxId, { ignoreBackoff: true });
}

function createAdminRouter({ db, authAdmin, profileService, founderService, sessionService, authenticateAdminMiddleware, auditLogService, platformOutboxService }) {
  const router = express.Router();
  const resolvedAuthAdmin = authAdmin || (profileService && profileService.authAdmin) || (sessionService && sessionService.authAdmin) || null;
  const outboxService = platformOutboxService || (
    db && typeof db.collection === 'function'
      ? new PlatformOutboxService(db, resolvedAuthAdmin, { auditLogService })
      : null
  );

  const requireAdmin = authenticateAdminMiddleware || ((req, res) => {
    return res.status(503).json({ error: 'service_unavailable', error_description: 'Admin authentication unavailable.' });
  });

  const requirePlatformAdmin = (req, res, next) => {
    requireAdmin(req, res, () => {
      const adminCtx = req.adminContext;
      const isPlatformAdmin = Boolean(
        (adminCtx && adminCtx.isPlatformAdmin === true) ||
        req.adminRole === 'platform_admin'
      );
      if (!req.isAdmin || !adminCtx || !isPlatformAdmin) {
        return res.status(403).json({
          error: 'forbidden',
          error_description: 'PLATFORM_ADMIN_REQUIRED: Platform administrator authorization required for global operations.'
        });
      }
      return next();
    });
  };

  const ensureAuditDependencies = (res, req) => {
    if (!auditLogService || typeof auditLogService.buildAdminAuditRecord !== 'function' || typeof auditLogService.writeInTransaction !== 'function') {
      res.status(503).json({
        error: 'service_unavailable',
        error_description: 'Audit logging service unavailable.',
        correlationId: req.correlationId
      });
      return false;
    }
    if (!db || typeof db.runTransaction !== 'function') {
      res.status(503).json({
        error: 'service_unavailable',
        error_description: 'Transactional persistence unavailable.',
        correlationId: req.correlationId
      });
      return false;
    }
    return true;
  };

  const buildPlatformAuditPrepared = (req, { operation, targetUid, outcome = 'success', metadata = {} }) => {
    const adminCtx = req.adminContext || {};
    const user = req.user || {};
    const auditId = `aud_${crypto.randomUUID()}`;
    return auditLogService.buildAdminAuditRecord({
      auditId,
      actorUid: adminCtx.uid || req.uid || user.uid || 'unknown',
      actorEmail: user.email || null,
      actorTenantId: adminCtx.tenantId || 'lanzar',
      actorRole: 'platform_admin',
      targetTenantId: 'lanzar',
      clientId: targetUid,
      operation,
      outcome,
      correlationId: req.correlationId || req.headers['x-correlation-id'] || req.headers['x-request-id'] || null,
      metadata: { ...metadata, targetUid }
    });
  };

  const handleAdminError = (res, req, status, errorCode, publicDescription, err) => {
    console.error(`[ADMIN ROUTE ERROR] ${errorCode}`, {
      correlationId: req.correlationId,
      message: err && err.message ? err.message : 'Unknown error'
    });
    return res.status(status).json({
      error: errorCode,
      error_description: publicDescription,
      correlationId: req.correlationId
    });
  };

  const sendIdempotentReplay = async (res, req, existing) => {
    let liveStatus = existing.status || 'PENDING_EXTERNAL_AUTH';
    if (existing.outboxId) {
      const outboxSnap = await db.collection('security_outbox').doc(existing.outboxId).get();
      if (outboxSnap.exists) {
        liveStatus = outboxSnap.data().status || liveStatus;
      }
    }

    if (liveStatus === 'COMPLETED') {
      return res.status(200).json({
        ...(existing.responseSnapshot || {}),
        auditId: existing.auditId,
        outboxId: existing.outboxId,
        operationVersion: existing.operationVersion || null,
        revocationVersion: existing.revocationVersion || null,
        idempotentReplay: true,
        externalAuthStatus: 'completed'
      });
    }
    if (liveStatus === 'SUPERSEDED') {
      return res.status(200).json({
        ...(existing.responseSnapshot || {}),
        auditId: existing.auditId,
        outboxId: existing.outboxId,
        operationVersion: existing.operationVersion || null,
        revocationVersion: existing.revocationVersion || null,
        idempotentReplay: true,
        superseded: true,
        externalAuthStatus: 'superseded'
      });
    }
    if (liveStatus === 'DEAD_LETTER') {
      return res.status(503).json({
        error: 'external_auth_sync_dead_letter',
        error_description: 'Firestore state committed, but Firebase Auth synchronization exhausted retries and requires administrative redrive.',
        outboxId: existing.outboxId,
        auditId: existing.auditId,
        idempotentReplay: true,
        externalAuthStatus: 'dead_letter',
        correlationId: req.correlationId
      });
    }
    return res.status(503).json({
      error: 'external_auth_sync_pending',
      error_description: 'Firestore state and audit already committed for this Idempotency-Key; Firebase Auth synchronization is pending reconciliation.',
      outboxId: existing.outboxId,
      auditId: existing.auditId,
      idempotentReplay: true,
      externalAuthStatus: 'pending',
      correlationId: req.correlationId
    });
  };

  router.get('/users', requirePlatformAdmin, async (req, res) => {
    try {
      const { query: searchQuery, status, limit = 25 } = req.query;
      let ref = db.collection('users').limit(Number(limit));

      if (status) {
        ref = ref.where('status', '==', status);
      }

      const snap = await ref.get();
      let users = snap.docs.map(doc => doc.data());

      if (searchQuery) {
        const cleanQuery = searchQuery.trim().toLowerCase();
        users = users.filter(u =>
          (u.email && u.email.toLowerCase().includes(cleanQuery)) ||
          (u.displayName && u.displayName.toLowerCase().includes(cleanQuery)) ||
          (u.uid && u.uid.toLowerCase().includes(cleanQuery))
        );
      }

      return res.json({ users, count: users.length });
    } catch (err) {
      return handleAdminError(res, req, 500, 'server_error', 'Failed to list users.', err);
    }
  });

  router.get('/users/:uid', requirePlatformAdmin, async (req, res) => {
    try {
      const profile = await profileService.getUserProfile(req.params.uid);
      if (!profile) return res.status(404).json({ error: 'user_not_found' });

      const [founders, sessions] = await Promise.all([
        founderService.listUserFounders(req.params.uid),
        sessionService.listUserSessions(req.params.uid)
      ]);

      return res.json({
        ...profile,
        authoritativeFounders: founders,
        activeSessions: sessions
      });
    } catch (err) {
      return handleAdminError(res, req, 500, 'server_error', 'Failed to retrieve user profile.', err);
    }
  });

  router.post('/users/:uid/suspend', requirePlatformAdmin, async (req, res) => {
    const { status, reason } = req.body || {};
    if (!['active', 'suspended'].includes(status)) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Invalid status. Must be "active" or "suspended".',
        correlationId: req.correlationId
      });
    }
    if (!ensureAuditDependencies(res, req)) return;

    const uid = req.params.uid;
    const adminCtx = req.adminContext || {};
    const actorUid = adminCtx.uid || req.uid || 'unknown';
    const actorTenantId = adminCtx.tenantId || 'lanzar';
    const normalizedReason = String(reason || '').slice(0, 255);

    const idem = parseAndScopeIdempotencyKey(req, {
      actorUid,
      actorTenantId,
      operation: 'platform.user.status_update',
      targetUid: uid,
      canonicalPayload: { status, reason: normalizedReason }
    });
    if (!idem.valid) {
      return res.status(400).json({
        error: 'invalid_idempotency_key',
        error_description: idem.error,
        correlationId: req.correlationId
      });
    }

    const isSuspended = status === 'suspended';
    const outboxId = `outbox_${crypto.randomUUID()}`;
    const preparedAudit = buildPlatformAuditPrepared(req, {
      operation: 'platform.user.status_update',
      targetUid: uid,
      outcome: 'pending_external_auth',
      metadata: { status, reason: normalizedReason || null, outboxId, idempotencyDocId: idem.idempotencyDocId }
    });
    const responseSnapshot = { success: true, uid, status };

    let txOutcome;
    try {
      const nowMs = Date.now();
      const nowIso = new Date(nowMs).toISOString();
      const expiresAt = new Date(nowMs + IDEMPOTENCY_TTL_MS).toISOString();
      const centralRevokedAt = Math.floor(nowMs / 1000);

      txOutcome = await db.runTransaction(async (tx) => {
        const idemRef = db.collection('admin_idempotency').doc(idem.idempotencyDocId);
        const idemSnap = await tx.get(idemRef);
        if (idemSnap.exists) {
          const existing = idemSnap.data();
          if (existing.requestHash !== idem.requestHash) {
            return { conflict: true };
          }
          return { replayed: true, existing };
        }

        const userRef = db.collection('users').doc(uid);
        const userSnap = await tx.get(userRef);
        const userData = userSnap.exists ? userSnap.data() : {};
        const currentOpVersion = Number(userData.desiredAuthVersion || 0);
        const operationVersion = currentOpVersion + 1;
        const currentRevVersion = Number(userData.desiredRevocationVersion || 0);
        const revocationVersion = isSuspended ? (currentRevVersion + 1) : currentRevVersion;

        let sessionsSnap = null;
        let centralSnap = null;
        if (isSuspended) {
          sessionsSnap = await tx.get(userRef.collection('sessions').where('revoked', '==', false));
          centralSnap = await tx.get(userRef.collection('central_sessions').where('revoked', '==', false));
        }

        const userPatch = {
          status,
          statusReason: normalizedReason,
          statusUpdatedBy: req.uid,
          statusUpdatedAt: FieldValue.serverTimestamp(),
          desiredAuthVersion: operationVersion,
          desiredAuthDisabled: isSuspended,
          desiredAuthUpdatedAt: nowIso
        };
        if (isSuspended) {
          userPatch.tokenVersion = FieldValue.increment(1);
          userPatch.updatedAt = FieldValue.serverTimestamp();
          userPatch.desiredRevocationVersion = revocationVersion;
          userPatch.desiredRevokedAt = nowIso;
        }
        tx.set(userRef, userPatch, { merge: true });

        if (isSuspended && sessionsSnap) {
          sessionsSnap.forEach(doc => {
            tx.update(doc.ref, { revoked: true, revokedAt: nowIso, revokedBy: req.uid });
          });
        }
        if (isSuspended && centralSnap) {
          centralSnap.forEach(doc => {
            tx.update(doc.ref, { revoked: true, revokedAt: centralRevokedAt, revokedReason: 'account_suspended' });
          });
        }

        tx.create(db.collection('security_outbox').doc(outboxId), {
          outboxId,
          type: 'platform_admin_cross_service',
          operation: 'platform.user.status_update',
          targetUid: uid,
          actorUid,
          operationVersion,
          ...(isSuspended ? { revocationVersion, desiredRevokedAt: nowIso } : {}),
          correlationId: req.correlationId || null,
          status: 'PENDING_EXTERNAL_AUTH',
          payload: { disabled: isSuspended, status, reason: normalizedReason, revokeRefreshTokens: isSuspended },
          progress: { updateUserDone: false, revokeRefreshTokensDone: !isSuspended },
          auditId: preparedAudit.record.auditId,
          idempotencyDocId: idem.idempotencyDocId,
          attempts: 0,
          fencingToken: 0,
          leaseOwner: null,
          leaseExpiresAt: 0,
          nextRetryAt: 0,
          createdAt: nowIso,
          updatedAt: nowIso
        });

        tx.create(idemRef, {
          idempotencyDocId: idem.idempotencyDocId,
          scope: { actorUid, actorTenantId, operation: 'platform.user.status_update', targetUid: uid },
          requestHash: idem.requestHash,
          outboxId,
          auditId: preparedAudit.record.auditId,
          operationVersion,
          status: 'PENDING_EXTERNAL_AUTH',
          externalAuthStatus: 'pending',
          responseSnapshot,
          createdAt: nowIso,
          updatedAt: nowIso,
          expiresAt,
          ttlExpiresAt: computeTtlDate(expiresAt, ADMIN_IDEMPOTENCY_TTL_GRACE_MS)
        });

        const versionedAudit = {
          ...preparedAudit,
          record: {
            ...preparedAudit.record,
            metadata: { ...preparedAudit.record.metadata, operationVersion }
          }
        };
        auditLogService.writeInTransaction(tx, versionedAudit);
        return { replayed: false, conflict: false, operationVersion };
      });
    } catch (err) {
      return handleAdminError(res, req, 503, 'audit_persistence_failed', 'Operation aborted: administrative state and audit log could not be persisted.', err);
    }

    if (txOutcome.conflict) {
      return res.status(409).json({
        error: 'idempotency_key_conflict',
        error_description: 'Idempotency-Key was already used with a different request payload.',
        correlationId: req.correlationId
      });
    }
    if (txOutcome.replayed) {
      return sendIdempotentReplay(res, req, txOutcome.existing);
    }

    const syncResult = await outboxService.processEventById(outboxId);
    if (syncResult.status !== 'COMPLETED') {
      return res.status(503).json({
        error: syncResult.status === 'DEAD_LETTER' ? 'external_auth_sync_dead_letter' : 'external_auth_sync_pending',
        error_description: 'Firestore state and audit recorded; Firebase Auth synchronization pending reconciliation.',
        outboxId,
        auditId: preparedAudit.record.auditId,
        externalAuthStatus: syncResult.status === 'DEAD_LETTER' ? 'dead_letter' : 'pending',
        correlationId: req.correlationId
      });
    }

    return res.json({
      ...responseSnapshot,
      auditId: preparedAudit.record.auditId,
      outboxId,
      operationVersion: txOutcome.operationVersion,
      externalAuthStatus: syncResult.status === 'SUPERSEDED' ? 'superseded' : 'completed'
    });
  });

  router.post('/users/:uid/founders', requirePlatformAdmin, async (req, res) => {
    const { programId, founderNumber, title, grantReason } = req.body || {};
    if (!programId || !grantReason) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'programId and grantReason are required.',
        correlationId: req.correlationId
      });
    }
    if (!ensureAuditDependencies(res, req)) return;

    try {
      const preparedAudit = buildPlatformAuditPrepared(req, {
        operation: 'platform.founder.grant',
        targetUid: req.params.uid,
        metadata: { programId, founderNumber: founderNumber || null }
      });
      const result = await founderService.grantFounderDesignation({
        uid: req.params.uid,
        programId,
        founderNumber,
        title,
        grantReason,
        grantedBy: req.uid,
        ipAddress: req.ip,
        auditLogService,
        auditPrepared: preparedAudit
      });
      return res.json({ ...result, auditId: preparedAudit.record.auditId });
    } catch (err) {
      if (err && err.message && err.message.startsWith('Invalid founder programId')) {
        return handleAdminError(res, req, 400, 'founder_grant_error', 'Invalid founder program specified.', err);
      }
      return handleAdminError(res, req, 503, 'audit_persistence_failed', 'Founder grant aborted: atomic state and audit persistence failed.', err);
    }
  });

  router.delete('/users/:uid/founders/:programId', requirePlatformAdmin, async (req, res) => {
    const { revocationReason } = req.body || {};
    if (!revocationReason) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'revocationReason is required.',
        correlationId: req.correlationId
      });
    }
    if (!ensureAuditDependencies(res, req)) return;

    try {
      const preparedAudit = buildPlatformAuditPrepared(req, {
        operation: 'platform.founder.revoke',
        targetUid: req.params.uid,
        metadata: { programId: req.params.programId, revocationReason }
      });
      const result = await founderService.revokeFounderDesignation({
        uid: req.params.uid,
        programId: req.params.programId,
        revocationReason,
        revokedBy: req.uid,
        ipAddress: req.ip,
        auditLogService,
        auditPrepared: preparedAudit
      });
      return res.json({ ...result, auditId: preparedAudit.record.auditId });
    } catch (err) {
      if (err && err.message && err.message.includes('does not exist or is already inactive')) {
        return handleAdminError(res, req, 404, 'founder_not_found', 'Founder designation does not exist or is already inactive.', err);
      }
      return handleAdminError(res, req, 503, 'audit_persistence_failed', 'Founder revocation aborted: atomic state and audit persistence failed.', err);
    }
  });

  router.post('/users/:uid/sessions/revoke-all', requirePlatformAdmin, async (req, res) => {
    if (!ensureAuditDependencies(res, req)) return;

    const uid = req.params.uid;
    const adminCtx = req.adminContext || {};
    const actorUid = adminCtx.uid || req.uid || 'unknown';
    const actorTenantId = adminCtx.tenantId || 'lanzar';

    const idem = parseAndScopeIdempotencyKey(req, {
      actorUid,
      actorTenantId,
      operation: 'platform.user.sessions_revoke_all',
      targetUid: uid,
      canonicalPayload: {}
    });
    if (!idem.valid) {
      return res.status(400).json({
        error: 'invalid_idempotency_key',
        error_description: idem.error,
        correlationId: req.correlationId
      });
    }

    const outboxId = `outbox_${crypto.randomUUID()}`;
    const preparedAudit = buildPlatformAuditPrepared(req, {
      operation: 'platform.user.sessions_revoke_all',
      targetUid: uid,
      outcome: 'pending_external_auth',
      metadata: { outboxId, idempotencyDocId: idem.idempotencyDocId }
    });

    let txOutcome;
    try {
      const nowMs = Date.now();
      const nowIso = new Date(nowMs).toISOString();
      const expiresAt = new Date(nowMs + IDEMPOTENCY_TTL_MS).toISOString();
      const centralRevokedAt = Math.floor(nowMs / 1000);

      txOutcome = await db.runTransaction(async (tx) => {
        const idemRef = db.collection('admin_idempotency').doc(idem.idempotencyDocId);
        const idemSnap = await tx.get(idemRef);
        if (idemSnap.exists) {
          const existing = idemSnap.data();
          if (existing.requestHash !== idem.requestHash) {
            return { conflict: true };
          }
          return { replayed: true, existing };
        }

        const userRef = db.collection('users').doc(uid);
        const userSnap = await tx.get(userRef);
        const userData = userSnap.exists ? userSnap.data() : {};
        const currentRevVersion = Number(userData.desiredRevocationVersion || 0);
        const revocationVersion = currentRevVersion + 1;

        const sessionsSnap = await tx.get(userRef.collection('sessions').where('revoked', '==', false));
        const centralSnap = await tx.get(userRef.collection('central_sessions').where('revoked', '==', false));

        const revokedSessionsCount = sessionsSnap.size;
        tx.set(userRef, {
          tokenVersion: FieldValue.increment(1),
          desiredRevocationVersion: revocationVersion,
          desiredRevokedAt: nowIso,
          desiredRevokedAtIso: nowIso,
          desiredAuthUpdatedAt: nowIso,
          updatedAt: FieldValue.serverTimestamp()
        }, { merge: true });

        sessionsSnap.forEach(doc => {
          tx.update(doc.ref, { revoked: true, revokedAt: nowIso, revokedBy: req.uid });
        });
        centralSnap.forEach(doc => {
          tx.update(doc.ref, { revoked: true, revokedAt: centralRevokedAt, revokedReason: 'global_revocation' });
        });

        const responseSnapshot = { success: true, revokedSessionsCount };

        tx.create(db.collection('security_outbox').doc(outboxId), {
          outboxId,
          type: 'platform_admin_cross_service',
          operation: 'platform.user.sessions_revoke_all',
          targetUid: uid,
          actorUid,
          revocationVersion,
          desiredRevokedAt: nowIso,
          correlationId: req.correlationId || null,
          status: 'PENDING_EXTERNAL_AUTH',
          payload: { revokeRefreshTokens: true },
          progress: { revokeRefreshTokensDone: false },
          auditId: preparedAudit.record.auditId,
          idempotencyDocId: idem.idempotencyDocId,
          attempts: 0,
          fencingToken: 0,
          leaseOwner: null,
          leaseExpiresAt: 0,
          nextRetryAt: 0,
          createdAt: nowIso,
          updatedAt: nowIso
        });

        tx.create(idemRef, {
          idempotencyDocId: idem.idempotencyDocId,
          scope: { actorUid, actorTenantId, operation: 'platform.user.sessions_revoke_all', targetUid: uid },
          requestHash: idem.requestHash,
          outboxId,
          auditId: preparedAudit.record.auditId,
          revocationVersion,
          status: 'PENDING_EXTERNAL_AUTH',
          externalAuthStatus: 'pending',
          responseSnapshot,
          createdAt: nowIso,
          updatedAt: nowIso,
          expiresAt,
          ttlExpiresAt: computeTtlDate(expiresAt, ADMIN_IDEMPOTENCY_TTL_GRACE_MS)
        });

        const versionedAudit = {
          ...preparedAudit,
          record: {
            ...preparedAudit.record,
            metadata: { ...preparedAudit.record.metadata, revocationVersion, desiredRevokedAt: nowIso }
          }
        };
        auditLogService.writeInTransaction(tx, versionedAudit);
        return { replayed: false, conflict: false, responseSnapshot, revocationVersion };
      });
    } catch (err) {
      return handleAdminError(res, req, 503, 'audit_persistence_failed', 'Session revocation aborted: atomic state and audit persistence failed.', err);
    }

    if (txOutcome.conflict) {
      return res.status(409).json({
        error: 'idempotency_key_conflict',
        error_description: 'Idempotency-Key was already used with a different request payload.',
        correlationId: req.correlationId
      });
    }
    if (txOutcome.replayed) {
      return sendIdempotentReplay(res, req, txOutcome.existing);
    }

    const syncResult = await outboxService.processEventById(outboxId);
    if (syncResult.status !== 'COMPLETED') {
      return res.status(503).json({
        error: syncResult.status === 'DEAD_LETTER' ? 'external_auth_sync_dead_letter' : 'external_auth_sync_pending',
        error_description: 'Firestore sessions revoked and audit recorded; Firebase Auth synchronization pending reconciliation.',
        outboxId,
        auditId: preparedAudit.record.auditId,
        revokedSessionsCount: txOutcome.responseSnapshot.revokedSessionsCount,
        externalAuthStatus: syncResult.status === 'DEAD_LETTER' ? 'dead_letter' : 'pending',
        correlationId: req.correlationId
      });
    }

    return res.json({
      ...txOutcome.responseSnapshot,
      auditId: preparedAudit.record.auditId,
      outboxId,
      revocationVersion: txOutcome.revocationVersion,
      externalAuthStatus: syncResult.status === 'SUPERSEDED' ? 'superseded' : 'completed'
    });
  });

  router.get('/outbox/:outboxId', requirePlatformAdmin, async (req, res) => {
    try {
      const snap = await db.collection('security_outbox').doc(req.params.outboxId).get();
      if (!snap.exists) {
        return res.status(404).json({ error: 'outbox_event_not_found', correlationId: req.correlationId });
      }
      return res.json({ event: snap.data() });
    } catch (err) {
      return handleAdminError(res, req, 500, 'server_error', 'Failed to inspect outbox event.', err);
    }
  });

  router.post('/outbox/:outboxId/redrive', requirePlatformAdmin, async (req, res) => {
    if (!ensureAuditDependencies(res, req)) return;
    try {
      const adminCtx = req.adminContext || {};
      const user = req.user || {};
      const result = await outboxService.redriveEvent({
        outboxId: req.params.outboxId,
        actorUid: adminCtx.uid || req.uid || 'unknown',
        actorEmail: user.email || null,
        actorTenantId: adminCtx.tenantId || 'lanzar',
        correlationId: req.correlationId || null,
        executeImmediately: true
      });
      return res.json(result);
    } catch (err) {
      if (err && err.message === 'OUTBOX_EVENT_NOT_FOUND') {
        return handleAdminError(res, req, 404, 'outbox_event_not_found', 'Outbox event not found.', err);
      }
      if (err && err.message === 'OUTBOX_ALREADY_COMPLETED') {
        return handleAdminError(res, req, 409, 'outbox_already_completed', 'Outbox event is already completed.', err);
      }
      if (err && err.message === 'OUTBOX_SUPERSEDED') {
        return handleAdminError(res, req, 409, 'outbox_superseded', 'Outbox event was superseded by a newer operation.', err);
      }
      if (err && err.message === 'OUTBOX_LEASE_ACTIVE') {
        return handleAdminError(res, req, 409, 'outbox_lease_active', 'Outbox event is currently leased by an active worker.', err);
      }
      return handleAdminError(res, req, 503, 'redrive_failed', 'Administrative redrive failed.', err);
    }
  });

  router.get('/audit-log', requirePlatformAdmin, async (req, res) => {
    try {
      const { limit = 50 } = req.query;
      const snap = await db.collection('security_logs')
        .orderBy('timestamp', 'desc')
        .limit(Number(limit))
        .get();

      const logs = snap.docs.map(doc => doc.data());
      return res.json({ logs, count: logs.length });
    } catch (err) {
      return handleAdminError(res, req, 500, 'server_error', 'Failed to retrieve audit logs.', err);
    }
  });

  router.get('/telemetry', requirePlatformAdmin, async (req, res) => {
    try {
      const [usersSnap, logsSnap, outboxDlqSnap, outboxRetrySnap, outboxPendingSnap, recDlqSnap, workerHealthSnap] = await Promise.all([
        db.collection('users').get(),
        db.collection('security_logs').limit(10).get(),
        db.collection('security_outbox').where('status', '==', 'DEAD_LETTER').get(),
        db.collection('security_outbox').where('status', '==', 'FAILED_RETRYABLE').get(),
        db.collection('security_outbox').where('status', '==', 'PENDING_EXTERNAL_AUTH').get(),
        db.collection('auth_reconciliation').where('status', '==', 'DEAD_LETTER').get(),
        db.collection('system_worker_health').doc('outbox_worker').get()
      ]);

      let totalUsers = usersSnap.size;
      let activeUsers = 0;
      let suspendedUsers = 0;
      let mfaEnrolledCount = 0;
      let founderCount = 0;

      usersSnap.forEach(doc => {
        const d = doc.data();
        if (d.status === 'suspended') suspendedUsers++;
        else activeUsers++;
        if (d.mfaEnabled) mfaEnrolledCount++;
        if (d.derivedBadges && d.derivedBadges.length > 0) founderCount++;
      });

      const nowMs = Date.now();
      let worker = { status: 'unknown', workerId: null, lastHeartbeatAt: null, ageSeconds: null };
      if (workerHealthSnap.exists) {
        const wh = workerHealthSnap.data() || {};
        const lastMs = Number(wh.lastHeartbeatMs || (wh.lastHeartbeatAt ? Date.parse(wh.lastHeartbeatAt) : NaN));
        const ageSeconds = Number.isFinite(lastMs) ? Math.max(0, Math.floor((nowMs - lastMs) / 1000)) : null;
        const isHealthy = ageSeconds !== null && ageSeconds <= 90;
        worker = {
          status: isHealthy ? 'healthy' : 'stale',
          workerId: wh.workerId || null,
          lastHeartbeatAt: wh.lastHeartbeatAt || null,
          ageSeconds
        };
      }

      const deadLetterAlert = outboxDlqSnap.size > 0 || recDlqSnap.size > 0;

      return res.json({
        status: deadLetterAlert || worker.status === 'stale' ? 'degraded' : 'nominal',
        serverTime: new Date(nowMs).toISOString(),
        uptimeSeconds: Math.floor(process.uptime()),
        totalUsers,
        activeUsers,
        suspendedUsers,
        mfaEnrolledCount,
        founderCount,
        recentLogsCount: logsSnap.size,
        outbox: {
          deadLetterCount: outboxDlqSnap.size,
          failedRetryableCount: outboxRetrySnap.size,
          pendingCount: outboxPendingSnap.size
        },
        reconciliation: {
          deadLetterCount: recDlqSnap.size
        },
        worker,
        alerts: {
          deadLetterPresent: deadLetterAlert,
          workerStale: worker.status === 'stale'
        },
        environment: process.env.NODE_ENV || 'development'
      });
    } catch (err) {
      return handleAdminError(res, req, 500, 'server_error', 'Failed to retrieve telemetry.', err);
    }
  });

  router.get('/clients', requirePlatformAdmin, (req, res) => {
    try {
      const clientList = Object.values(clients).map(c => ({
        id: c.id,
        name: c.name,
        redirectUris: c.redirectUris,
        enabled: c.enabled !== false
      }));
      return res.json({ clients: clientList });
    } catch (err) {
      return handleAdminError(res, req, 500, 'server_error', 'Failed to list clients.', err);
    }
  });

  return router;
}

module.exports = { createAdminRouter, reconcilePlatformOutboxEvent };
