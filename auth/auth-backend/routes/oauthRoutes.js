// oauthRoutes.js
// OAuth 2.0 & PKCE Authorization and Token Exchange Endpoints for LANZAR ID

const express = require('express');
const crypto = require('crypto');
const { getClient } = require('../clients');
const { createMfaSignedToken, verifyMfaSignedToken } = require('../mfaService');

function createOAuthRouter({ db, authAdmin, codeStore, sessionService, isUserAdmin, reconcileCustomerAccount }) {
  const router = express.Router();

  router.post('/authorize', async (req, res) => {
    try {
      const { idToken, client_id, redirect_uri, state, code_challenge, code_challenge_method, mfa_proof } = req.body;
      if (!idToken || !client_id || !redirect_uri || !state || !code_challenge || code_challenge_method !== 'S256') {
        return res.status(400).json({ error: 'invalid_request', error_description: 'Missing or invalid parameters' });
      }

      const client = getClient(client_id);
      if (!client || !client.enabled) {
        return res.status(400).json({ error: 'invalid_client', error_description: 'Unknown or disabled client' });
      }

      const normalizedRedirect = redirect_uri.replace(/\/+$/, '');
      const isAuthorized = client.redirectUris.some(uri => {
        const clean = uri.replace(/\/+$/, '');
        return clean === normalizedRedirect || normalizedRedirect.startsWith(clean + '/');
      });
      if (!isAuthorized) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'Unauthorized redirect URI' });
      }

      const decodedToken = await authAdmin.verifyIdToken(idToken, true);
      const uid = decodedToken.uid;
      const email = decodedToken.email;

      // Check account suspension
      const userDoc = await db.collection('users').doc(uid).get();
      if (userDoc.exists && userDoc.data().status === 'suspended') {
        return res.status(403).json({ error: 'account_suspended', error_description: 'This account has been suspended.' });
      }

      if (reconcileCustomerAccount) {
        await reconcileCustomerAccount({
          uid,
          email,
          displayName: decodedToken.name,
          businessName: '',
          dispatchOptIn: false
        });
      }

      const isAdmin = await isUserAdmin(uid, email);
      const mfaDoc = await db.collection('mfa_factors').doc(uid).get();
      const hasMfa = mfaDoc.exists && mfaDoc.data().enabled;

      if (isAdmin || hasMfa) {
        let mfaVerified = false;
        if (mfa_proof) {
          const proofPayload = verifyMfaSignedToken(mfa_proof);
          if (proofPayload && proofPayload.uid === uid && proofPayload.action === 'mfa_verified') {
            mfaVerified = true;
          }
        }

        if (!mfaVerified) {
          const mfaSession = createMfaSignedToken({
            uid,
            email,
            action: 'mfa_challenge',
            isAdmin
          }, 600000);

          return res.status(403).json({
            error: 'mfa_required',
            error_description: isAdmin && !hasMfa ? 'Administrator accounts require MFA enrollment.' : 'Multi-Factor Authentication required.',
            mfa_required: true,
            enrollment_required: isAdmin && !hasMfa,
            mfa_session: mfaSession,
            methods: hasMfa ? ['totp', 'recovery'] : ['totp']
          });
        }
      }

      // Remediation for Finding C: Persist negotiated PKCE code challenge method in code record
      const code = await codeStore.createCode({
        uid,
        clientId: client_id,
        redirectUri: redirect_uri,
        codeChallenge: code_challenge,
        codeChallengeMethod: code_challenge_method,
        mfaVerified: isAdmin || hasMfa
      });

      return res.json({ code, state });
    } catch (error) {
      console.error('[AUTH ERROR]', error);
      return res.status(500).json({ error: 'server_error', error_description: error.message });
    }
  });

  router.post('/exchange', async (req, res) => {
    try {
      const { code, client_id, redirect_uri, code_verifier } = req.body;
      if (!code || !client_id || !redirect_uri || !code_verifier) {
        return res.status(400).json({ error: 'invalid_request' });
      }

      const record = await codeStore.getCode(code);
      if (!record || record.used || Date.now() > record.expiresAt) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'Code invalid or expired.' });
      }

      const reqRedirect = redirect_uri.replace(/\/+$/, '');
      const recRedirect = record.redirectUri.replace(/\/+$/, '');
      if (record.clientId !== client_id || reqRedirect !== recRedirect) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'Client or redirect URI mismatch.' });
      }

      // Remediation for Finding C: Enforce validated challenge method and prevent downgrade
      if (record.codeChallengeMethod !== 'S256') {
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Unsupported or mismatched PKCE challenge method.'
        });
      }

      const hash = crypto.createHash('sha256').update(code_verifier).digest('base64url');
      if (hash !== record.codeChallenge) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE challenge mismatch.' });
      }

      await codeStore.markUsed(code);

      // Create individual active session in Firestore
      const sessionRecord = await sessionService.createSession({
        uid: record.uid,
        clientId: client_id,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });

      // Mint custom token with session claims
      const customToken = await authAdmin.createCustomToken(record.uid, {
        session_id: sessionRecord.sessionId,
        tenant_id: 'lanzar',
        client_id
      });

      return res.json({
        custom_token: customToken,
        session_id: sessionRecord.sessionId,
        expires_in: 3600
      });
    } catch (error) {
      console.error('[EXCHANGE ERROR]', error);
      return res.status(500).json({ error: 'server_error', error_description: error.message });
    }
  });

  return router;
}

module.exports = { createOAuthRouter };
