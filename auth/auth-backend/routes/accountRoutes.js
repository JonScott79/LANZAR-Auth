// accountRoutes.js
// Registration, provisioning, and password recovery endpoints for LANZAR ID

const express = require('express');
const crypto = require('crypto');
const util = require('util');
const { FieldValue } = require('firebase-admin/firestore');
const { recordSecurityEvent } = require('../auditService');
const { oauthAuthorizeLimiter } = require('../middleware/rateLimiter');

const scryptAsync = util.promisify(crypto.scrypt);

function createAccountRouter({ db, authAdmin }) {
  const router = express.Router();

  async function reconcileCustomerAccount({ uid, email, displayName, businessName, dispatchOptIn, emailVerified = false }) {
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
    } else if (Boolean(emailVerified) && !userSnap.data().emailVerified) {
      await userRef.update({
        emailVerified: true,
        updatedAt: FieldValue.serverTimestamp()
      });
    }

    if (!userSnap.exists) {
      await userRef.set({
        uid,
        tenantId: 'lanzar',
        displayName: resolvedName,
        email: normalizedEmail,
        emailVerified: Boolean(emailVerified),
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
    } else if (Boolean(emailVerified) && !userSnap.data().emailVerified) {
      await userRef.update({
        emailVerified: true,
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

  router.post('/register', oauthAuthorizeLimiter, async (req, res) => {
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

  router.post('/provision', oauthAuthorizeLimiter, async (req, res) => {
    try {
      const { idToken, fullName, businessName, dispatchOptIn } = req.body;
      if (!idToken) return res.status(400).json({ error: 'missing_id_token' });

      const decoded = await authAdmin.verifyIdToken(idToken, true);
      await reconcileCustomerAccount({
        uid: decoded.uid,
        email: decoded.email,
        displayName: fullName || decoded.name,
        businessName: businessName || '',
        dispatchOptIn: Boolean(dispatchOptIn),
        emailVerified: Boolean(decoded.email_verified)
      });

      return res.json({ success: true, uid: decoded.uid });
    } catch (err) {
      return res.status(401).json({ error: 'invalid_token', error_description: err.message });
    }
  });

  router.post('/password/forgot', oauthAuthorizeLimiter, async (req, res) => {
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

  async function findLegacyPythosAccount(normalizedEmail) {
    const accountsCol = db.collection('pythos').doc('app').collection('lanzar_id_accounts');
    const deterministicUid = 'lanzar_' + crypto.createHash('sha256').update(normalizedEmail).digest('hex').slice(0, 20);

    const directSnap = await accountsCol.doc(deterministicUid).get();
    if (directSnap.exists) {
      return { docId: directSnap.id, data: directSnap.data(), deterministicUid };
    }

    const emailQuery = accountsCol.where('email', '==', normalizedEmail);
    const emailSnap = await (typeof emailQuery.limit === 'function' ? emailQuery.limit(1).get() : emailQuery.get());
    if (!emailSnap.empty) {
      return { docId: emailSnap.docs[0].id, data: emailSnap.docs[0].data(), deterministicUid };
    }

    const normQuery = accountsCol.where('normalizedEmail', '==', normalizedEmail);
    const normSnap = await (typeof normQuery.limit === 'function' ? normQuery.limit(1).get() : normQuery.get());
    if (!normSnap.empty) {
      return { docId: normSnap.docs[0].id, data: normSnap.docs[0].data(), deterministicUid };
    }

    return null;
  }

  async function verifyLegacyScryptPassword(password, salt, expectedHex) {
    if (!password || !salt || !expectedHex) return false;
    const cleanedHex = String(expectedHex).trim();
    if (!/^[0-9a-f]+$/i.test(cleanedHex) || cleanedHex.length % 2 !== 0) return false;
    const derived = await scryptAsync(String(password), String(salt), 64, { N: 16384, r: 8, p: 1 });
    const expected = Buffer.from(cleanedHex, 'hex');
    if (derived.length !== expected.length) return false;
    return crypto.timingSafeEqual(derived, expected);
  }

  router.post('/login/legacy-bridge', oauthAuthorizeLimiter, async (req, res) => {
    try {
      const { email, password } = req.body || {};
      if (typeof email !== 'string' || typeof password !== 'string' || !email.trim() || !password) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'Email and password are required.' });
      }

      const normalizedEmail = email.trim().toLowerCase();
      const legacy = await findLegacyPythosAccount(normalizedEmail);
      if (!legacy || !legacy.data || !legacy.data.passwordSalt || !legacy.data.passwordHash) {
        return res.status(401).json({ error: 'invalid_credentials', error_description: 'Invalid email or password.' });
      }

      const passwordValid = await verifyLegacyScryptPassword(password, legacy.data.passwordSalt, legacy.data.passwordHash);
      if (!passwordValid) {
        return res.status(401).json({ error: 'invalid_credentials', error_description: 'Invalid email or password.' });
      }

      const legacyUid = legacy.data.uid || legacy.docId || legacy.deterministicUid;
      let userRecord = null;
      try {
        userRecord = await authAdmin.getUserByEmail(normalizedEmail);
      } catch (err) {
        if (err.code !== 'auth/user-not-found') throw err;
      }

      if (!userRecord && legacy.data.linkedGoogleUid) {
        try {
          const linkedUser = await authAdmin.getUser(legacy.data.linkedGoogleUid);
          if (!linkedUser.email || linkedUser.email.trim().toLowerCase() === normalizedEmail) {
            userRecord = linkedUser;
          }
        } catch (err) {
          if (err.code !== 'auth/user-not-found') throw err;
        }
      }

      const targetUid = userRecord ? userRecord.uid : legacyUid;
      const existingUserDoc = await db.collection('users').doc(targetUid).get();
      if (userRecord?.disabled || (existingUserDoc.exists && existingUserDoc.data().status === 'suspended')) {
        return res.status(403).json({ error: 'account_suspended', error_description: 'This account has been suspended.' });
      }

      if (userRecord) {
        const updatePayload = { password };
        if (!userRecord.displayName && legacy.data.displayName) {
          updatePayload.displayName = legacy.data.displayName;
        }
        userRecord = await authAdmin.updateUser(userRecord.uid, updatePayload);
      } else {
        const createPayload = {
          uid: legacyUid,
          email: normalizedEmail,
          password,
          displayName: legacy.data.displayName || normalizedEmail.split('@')[0],
          emailVerified: Boolean(legacy.data.emailVerified)
        };
        try {
          userRecord = await authAdmin.createUser(createPayload);
        } catch (createErr) {
          if (createErr.code === 'auth/uid-already-exists') {
            delete createPayload.uid;
            userRecord = await authAdmin.createUser(createPayload);
          } else {
            throw createErr;
          }
        }
      }

      await reconcileCustomerAccount({
        uid: userRecord.uid,
        email: normalizedEmail,
        displayName: legacy.data.displayName || userRecord.displayName || '',
        businessName: legacy.data.businessName || '',
        dispatchOptIn: false
      });

      const linkUpdate = {
        pythosLegacyUid: legacyUid,
        updatedAt: FieldValue.serverTimestamp()
      };
      if (legacy.data.linkedGoogleUid) {
        linkUpdate.linkedGoogleUid = legacy.data.linkedGoogleUid;
      }
      await db.collection('users').doc(userRecord.uid).set(linkUpdate, { merge: true });

      await recordSecurityEvent(db, {
        actorUid: userRecord.uid,
        actorEmail: normalizedEmail,
        action: 'account.legacy_password_bridged',
        targetUid: userRecord.uid,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        details: {
          pythosLegacyUid: legacyUid,
          linkedGoogleUid: legacy.data.linkedGoogleUid || null
        }
      });

      return res.json({
        success: true,
        bridged: true,
        uid: userRecord.uid
      });
    } catch (err) {
      console.error('[LEGACY BRIDGE ERROR]', err);
      return res.status(500).json({ error: 'server_error', error_description: err.message });
    }
  });

  return { router, reconcileCustomerAccount };
}

module.exports = { createAccountRouter };
