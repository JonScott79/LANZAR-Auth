// accountRoutes.js
// Registration, provisioning, and password recovery endpoints for LANZAR ID

const express = require('express');
const { FieldValue } = require('firebase-admin/firestore');
const { recordSecurityEvent } = require('../auditService');

function createAccountRouter({ db, authAdmin }) {
  const router = express.Router();

  async function reconcileCustomerAccount({ uid, email, displayName, businessName, dispatchOptIn }) {
    if (!uid || !email) return;
    const normalizedEmail = email.trim().toLowerCase();
    const customerRef = db.collection('customers').doc(uid);
    const userRef = db.collection('users').doc(uid);

    const [custSnap, userSnap] = await Promise.all([
      customerRef.get(),
      userRef.get()
    ]);

    const resolvedName = displayName || (custSnap.exists && custSnap.data().customerName) || normalizedEmail.split('@')[0];

    if (!custSnap.exists) {
      await customerRef.set({
        id: uid,
        customerId: uid,
        customerName: resolvedName,
        customerEmail: normalizedEmail,
        authEmail: normalizedEmail,
        businessName: businessName || '',
        role: 'customer',
        active: true,
        services: ['portal', 'tickets'],
        createdAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp()
      });
    }

    if (!userSnap.exists) {
      await userRef.set({
        uid,
        tenantId: 'lanzar',
        displayName: resolvedName,
        email: normalizedEmail,
        emailVerified: false,
        phoneNumber: null,
        phoneVerified: false,
        role: 'customer',
        status: 'active',
        tokenVersion: 1,
        derivedBadges: [],
        services: ['portal', 'tickets'],
        createdAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp()
      });
    }

    if (dispatchOptIn === true) {
      const subscriberRef = db.collection('mailing_list').doc(normalizedEmail);
      const subSnap = await subscriberRef.get();
      if (!subSnap.exists || subSnap.data().status !== 'unsubscribed') {
        await subscriberRef.set({
          email: normalizedEmail,
          fullName: resolvedName,
          status: 'active',
          source: 'lanzar-id',
          consentVersion: 'dispatch_v1',
          consentText: 'Send me The LANZAR Dispatch newsletter.',
          consentedAt: FieldValue.serverTimestamp(),
          updatedAt: FieldValue.serverTimestamp()
        }, { merge: true });
      }
    }
  }

  router.post('/register', async (req, res) => {
    try {
      const { email, password, fullName, businessName, dispatchOptIn } = req.body;
      if (!email || !password || !fullName) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'Name, email, and password are required.' });
      }
      if (password.length < 8) {
        return res.status(400).json({ error: 'weak_password', error_description: 'Password must be at least 8 characters.' });
      }

      const normalizedEmail = email.trim().toLowerCase();

      let userRecord;
      try {
        userRecord = await authAdmin.createUser({
          email: normalizedEmail,
          password,
          displayName: fullName.trim()
        });
      } catch (authErr) {
        if (authErr.code === 'auth/email-already-exists') {
          return res.status(409).json({ error: 'email_exists', error_description: 'An account with this email address already exists.' });
        }
        throw authErr;
      }

      await reconcileCustomerAccount({
        uid: userRecord.uid,
        email: normalizedEmail,
        displayName: fullName.trim(),
        businessName: businessName?.trim() || '',
        dispatchOptIn: Boolean(dispatchOptIn)
      });

      try {
        const verifyLink = await authAdmin.generateEmailVerificationLink(normalizedEmail);
        console.log(`[REGISTER VERIFY LINK GENERATED] for ${normalizedEmail}: ${verifyLink}`);
      } catch (linkErr) {
        console.warn('[REGISTER] Verification link generation notice:', linkErr.message);
      }

      await recordSecurityEvent(db, {
        actorUid: userRecord.uid,
        actorEmail: normalizedEmail,
        action: 'account.registered',
        targetUid: userRecord.uid,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });

      return res.json({
        success: true,
        uid: userRecord.uid,
        email: normalizedEmail
      });
    } catch (err) {
      console.error('[REGISTER ERROR]', err);
      return res.status(500).json({ error: 'server_error', error_description: err.message });
    }
  });

  router.post('/provision', async (req, res) => {
    try {
      const { idToken, fullName, businessName, dispatchOptIn } = req.body;
      if (!idToken) return res.status(400).json({ error: 'missing_id_token' });

      const decoded = await authAdmin.verifyIdToken(idToken, true);
      await reconcileCustomerAccount({
        uid: decoded.uid,
        email: decoded.email,
        displayName: fullName || decoded.name,
        businessName: businessName || '',
        dispatchOptIn: Boolean(dispatchOptIn)
      });

      return res.json({ success: true, uid: decoded.uid });
    } catch (err) {
      return res.status(401).json({ error: 'invalid_token', error_description: err.message });
    }
  });

  router.post('/password/forgot', async (req, res) => {
    try {
      const { email } = req.body;
      if (!email) return res.status(400).json({ error: 'missing_email' });

      const normalizedEmail = email.trim().toLowerCase();
      try {
        const resetLink = await authAdmin.generatePasswordResetLink(normalizedEmail);
        console.log(`[PASSWORD RESET LINK GENERATED] for ${normalizedEmail}: ${resetLink}`);
      } catch (e) {
        console.warn('[PASSWORD FORGOT] Non-fatal notification:', e.message);
      }

      return res.json({
        success: true,
        message: 'If an account exists with this email address, a password recovery link has been dispatched.'
      });
    } catch (err) {
      return res.status(500).json({ error: 'server_error', error_description: err.message });
    }
  });

  return { router, reconcileCustomerAccount };
}

module.exports = { createAccountRouter };
