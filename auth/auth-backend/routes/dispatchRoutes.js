// dispatchRoutes.js
// The Dispatch Newsletter subscription endpoints for LANZAR ID

const express = require('express');
const { FieldValue } = require('firebase-admin/firestore');
const { recordSecurityEvent } = require('../auditService');

function createDispatchRouter({ db, authenticateUserMiddleware }) {
  const router = express.Router();

  router.get('/status', authenticateUserMiddleware, async (req, res) => {
    try {
      const email = req.user.email?.toLowerCase();
      if (!email) return res.json({ subscribed: false });
      const doc = await db.collection('mailing_list').doc(email).get();
      const data = doc.exists ? doc.data() : null;
      return res.json({
        subscribed: Boolean(data && data.status === 'active'),
        status: data?.status || 'none',
        consentedAt: data?.consentedAt || data?.consentTimestamp || null,
        consentSource: data?.source || data?.consentSource || null
      });
    } catch (err) {
      return res.status(500).json({ error: 'server_error', error_description: err.message });
    }
  });

  router.post('/subscribe', authenticateUserMiddleware, async (req, res) => {
    try {
      const email = req.user.email?.toLowerCase();
      if (!email) return res.status(400).json({ error: 'missing_email' });
      const subscriberRef = db.collection('mailing_list').doc(email);
      await subscriberRef.set({
        email,
        uid: req.uid,
        fullName: req.user.name || '',
        status: 'active',
        source: 'my_lanzar_profile',
        consentVersion: 'dispatch_v1',
        consentText: 'Subscribed via My LANZAR account profile.',
        consentedAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp()
      }, { merge: true });

      await recordSecurityEvent(db, {
        actorUid: req.uid,
        actorEmail: email,
        action: 'newsletter.dispatch.subscribed',
        targetUid: req.uid,
        ipAddress: req.ip
      });

      return res.json({ success: true, subscribed: true });
    } catch (err) {
      return res.status(500).json({ error: 'server_error', error_description: err.message });
    }
  });

  router.post('/unsubscribe', authenticateUserMiddleware, async (req, res) => {
    try {
      const email = req.user.email?.toLowerCase();
      if (!email) return res.status(400).json({ error: 'missing_email' });
      const subscriberRef = db.collection('mailing_list').doc(email);
      await subscriberRef.set({
        status: 'unsubscribed',
        unsubscribedAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp()
      }, { merge: true });

      await recordSecurityEvent(db, {
        actorUid: req.uid,
        actorEmail: email,
        action: 'newsletter.dispatch.unsubscribed',
        targetUid: req.uid,
        ipAddress: req.ip
      });

      return res.json({ success: true, subscribed: false });
    } catch (err) {
      return res.status(500).json({ error: 'server_error', error_description: err.message });
    }
  });

  return router;
}

module.exports = { createDispatchRouter };
