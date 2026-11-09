// adminRoutes.js
// Administrative endpoints (Portal Mission Control) for LANZAR ID

const express = require('express');
const { clients } = require('../clients');

function createAdminRouter({ db, profileService, founderService, sessionService, authenticateAdminMiddleware }) {
  const router = express.Router();

  router.get('/users', authenticateAdminMiddleware, async (req, res) => {
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
      return res.status(500).json({ error: 'server_error', error_description: err.message });
    }
  });

  router.get('/users/:uid', authenticateAdminMiddleware, async (req, res) => {
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
      return res.status(500).json({ error: 'server_error', error_description: err.message });
    }
  });

  router.post('/users/:uid/suspend', authenticateAdminMiddleware, async (req, res) => {
    try {
      const { status, reason } = req.body;
      const result = await profileService.setAccountStatus(req.params.uid, status, reason, req.uid, req.ip);
      return res.json(result);
    } catch (err) {
      return res.status(400).json({ error: 'status_error', error_description: err.message });
    }
  });

  router.post('/users/:uid/founders', authenticateAdminMiddleware, async (req, res) => {
    try {
      const { programId, founderNumber, title, grantReason } = req.body;
      const result = await founderService.grantFounderDesignation({
        uid: req.params.uid,
        programId,
        founderNumber,
        title,
        grantReason,
        grantedBy: req.uid,
        ipAddress: req.ip
      });
      return res.json(result);
    } catch (err) {
      return res.status(400).json({ error: 'founder_grant_error', error_description: err.message });
    }
  });

  router.delete('/users/:uid/founders/:programId', authenticateAdminMiddleware, async (req, res) => {
    try {
      const { revocationReason } = req.body;
      const result = await founderService.revokeFounderDesignation({
        uid: req.params.uid,
        programId: req.params.programId,
        revocationReason,
        revokedBy: req.uid,
        ipAddress: req.ip
      });
      return res.json(result);
    } catch (err) {
      return res.status(400).json({ error: 'founder_revoke_error', error_description: err.message });
    }
  });

  router.post('/users/:uid/sessions/revoke-all', authenticateAdminMiddleware, async (req, res) => {
    try {
      const result = await sessionService.revokeAllSessions(req.params.uid, req.uid, req.ip);
      return res.json(result);
    } catch (err) {
      return res.status(500).json({ error: 'server_error', error_description: err.message });
    }
  });

  router.get('/audit-log', authenticateAdminMiddleware, async (req, res) => {
    try {
      const { limit = 50 } = req.query;
      const snap = await db.collection('security_logs')
        .orderBy('timestamp', 'desc')
        .limit(Number(limit))
        .get();

      const logs = snap.docs.map(doc => doc.data());
      return res.json({ logs, count: logs.length });
    } catch (err) {
      return res.status(500).json({ error: 'server_error', error_description: err.message });
    }
  });

  router.get('/telemetry', authenticateAdminMiddleware, async (req, res) => {
    try {
      const [usersSnap, logsSnap] = await Promise.all([
        db.collection('users').get(),
        db.collection('security_logs').limit(10).get()
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

      return res.json({
        status: 'nominal',
        serverTime: new Date().toISOString(),
        uptimeSeconds: Math.floor(process.uptime()),
        totalUsers,
        activeUsers,
        suspendedUsers,
        mfaEnrolledCount,
        founderCount,
        recentLogsCount: logsSnap.size,
        environment: process.env.NODE_ENV || 'development'
      });
    } catch (err) {
      return res.status(500).json({ error: 'server_error', error_description: err.message });
    }
  });

  router.get('/clients', authenticateAdminMiddleware, (req, res) => {
    try {
      const clientList = Object.values(clients).map(c => ({
        id: c.id,
        name: c.name,
        redirectUris: c.redirectUris,
        enabled: c.enabled !== false
      }));
      return res.json({ clients: clientList });
    } catch (err) {
      return res.status(500).json({ error: 'server_error', error_description: err.message });
    }
  });

  return router;
}

module.exports = { createAdminRouter };
