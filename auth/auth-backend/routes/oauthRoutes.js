// oauthRoutes.js
// OAuth 2.0 & PKCE Authorization and Token Exchange Endpoints for LANZAR ID

const express = require('express');
const crypto = require('crypto');
const { getClient } = require('../clients');
const { createMfaSignedToken, verifyMfaSignedToken } = require('../mfaService');
const { oauthAuthorizeLimiter, oauthExchangeLimiter } = require('../middleware/rateLimiter');
const { hashAuthorizationCode, generateRefreshToken } = require('../store');

const { ACCESS_TOKEN_TTL_SECONDS, hasScope, normalizeScope } = require('../services/oidcTokenService');

function createOAuthRouter({ db, authAdmin, codeStore, sessionService, isUserAdmin, reconcileCustomerAccount, oidcTokenService, clientRegistryService, getClientOverride }) {
  const router = express.Router();
  const resolveClientAsync = async (id) => {
    if (typeof getClientOverride === 'function') {
      const overridden = getClientOverride(id);
      if (overridden) return overridden;
    }
    if (clientRegistryService && typeof clientRegistryService.resolveClient === 'function') {
      return await clientRegistryService.resolveClient(id);
    }
    return getClient(id);
  };

  router.post('/authorize', oauthAuthorizeLimiter, async (req, res) => {
    try {
      const { idToken, client_id, redirect_uri, state, code_challenge, code_challenge_method, mfa_proof, scope, nonce } = req.body;
      if (!idToken || !client_id || !redirect_uri || !state || !code_challenge) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'Missing or invalid parameters' });
      }

      // Strict PKCE requirement: explicit S256 method required, reject missing or unsupported
      if (!code_challenge_method) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'code_challenge_method is required and must be S256'
        });
      }

      if (code_challenge_method !== 'S256') {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Unsupported code_challenge_method. Only S256 is supported.'
        });
      }

      const client = await resolveClientAsync(client_id);
      if (!client || !client.enabled) {
        return res.status(400).json({ error: 'invalid_client', error_description: 'Unknown or disabled client' });
      }

      const isAuthorized = clientRegistryService && typeof clientRegistryService.isRedirectUriAuthorized === 'function'
        ? clientRegistryService.isRedirectUriAuthorized(client, redirect_uri)
        : (Array.isArray(client.redirectUris) && client.redirectUris.includes(redirect_uri));
      if (!isAuthorized) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'Unauthorized redirect URI' });
      }

      if (nonce !== undefined && (typeof nonce !== 'string' || nonce.length === 0 || nonce.length > 256)) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'Invalid nonce parameter' });
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

      // Persist negotiated PKCE code challenge method in code record
      const code = await codeStore.createCode({
        uid,
        clientId: client_id,
        redirectUri: redirect_uri,
        codeChallenge: code_challenge,
        codeChallengeMethod: code_challenge_method,
        tenantId: client.tenantId || 'lanzar',
        scope: typeof scope === 'string' && scope.trim() ? normalizeScope(scope) : 'openid profile email',
        nonce: typeof nonce === 'string' && nonce ? nonce : null,
        userClaims: {
          email: decodedToken.email,
          emailVerified: decodedToken.email_verified,
          name: decodedToken.name,
          authTime: decodedToken.auth_time
        },
        mfaVerified: isAdmin || hasMfa
      });

      return res.json({ code, state });
    } catch (error) {
      console.error('[AUTH ERROR]', error);
      return res.status(500).json({ error: 'server_error', error_description: error.message });
    }
  });

  async function handleAuthorizationCodeGrant(req, res) {
    try {
      const { code, client_id, redirect_uri, code_verifier } = req.body || {};
      const idempotencyKey = req.headers['idempotency-key'] || (req.body && req.body.idempotency_key);

      if (!code || !client_id || !redirect_uri || !code_verifier) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'Missing required exchange parameters' });
      }

      const resolvedClient = await resolveClientAsync(client_id);
      if (!resolvedClient || !resolvedClient.enabled) {
        return res.status(400).json({ error: 'invalid_client', error_description: 'Unknown or disabled client.' });
      }
      if (clientRegistryService && typeof clientRegistryService.verifyClientCredentials === 'function') {
        if (!clientRegistryService.verifyClientCredentials(resolvedClient, req.body && req.body.client_secret)) {
          return res.status(401).json({ error: 'invalid_client', error_description: 'Invalid client credentials.' });
        }
      }

      // Mandatory capability enforcement for distributed two-phase redemption (Milestone 1.1)
      // Fail closed immediately if any required distributed store capability is unavailable.
      if (
        typeof codeStore.initiateRedemption !== 'function' ||
        typeof codeStore.registerStagedRecords !== 'function' ||
        typeof codeStore.finalizeRedemption !== 'function'
      ) {
        console.error('[SECURITY ERROR] Distributed codeStore capabilities incomplete or unavailable');
        return res.status(500).json({
          error: 'server_error',
          error_description: 'Distributed redemption store capabilities are incomplete or unavailable.'
        });
      }

      if (!idempotencyKey) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing mandatory Idempotency-Key header.'
        });
      }

      const claim = await codeStore.initiateRedemption({
        code,
        clientId: client_id,
        redirectUri: redirect_uri,
        codeVerifier: code_verifier,
        idempotencyKey
      });

      if (claim.status === 'INVALID_REQUEST') {
        return res.status(400).json({ error: 'invalid_request', error_description: claim.errorDescription });
      }
      if (claim.status === 'CLIENT_MISMATCH' || claim.status === 'REDIRECT_MISMATCH' || claim.status === 'PKCE_MISMATCH' || claim.status === 'NOT_FOUND' || claim.status === 'EXPIRED') {
        return res.status(400).json({ error: 'invalid_grant', error_description: claim.errorDescription });
      }
      if (claim.status === 'REPLAY_DETECTED') {
        return res.status(400).json({ error: 'invalid_grant', error_description: claim.errorDescription || 'Replay detected or ceremony compromised.' });
      }
      if (claim.status === 'IN_PROGRESS') {
        return res.status(409).json({ error: 'redemption_in_progress', error_description: 'Redemption in progress; please wait and retry.' });
      }
      if (claim.status === 'IDEMPOTENT_RECOVERY') {
        return res.json(claim.tokenReceipt);
      }

      if (claim.status !== 'SUCCESS') {
        return res.status(400).json({ error: 'invalid_grant', error_description: claim.errorDescription || 'Redemption claim failed.' });
      }

      const { codeHash, redemptionLockId, fenceToken, record } = claim;
      const sessionId = `sess_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
      const familyId = `fam_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
      const tenantId = record.tenantId || 'lanzar';
      const uid = record.uid;

      // Safe failure cleanup: Always inspect known sessionId and familyId to handle ambiguous Firestore create outcomes
      const safeCleanup = async (reason) => {
        if (typeof codeStore.handleRedemptionFailure === 'function') {
          try {
            await codeStore.handleRedemptionFailure({
              codeHash,
              redemptionLockId,
              fenceToken,
              uid,
              tenantId,
              sessionId,
              familyId,
              errorReason: reason
            });
          } catch (cleanupErr) {
            console.error('[CLEANUP ERROR] Failed to clean up redemption failure:', cleanupErr.message);
          }
        }
      };

      try {
        const now = new Date();
        const expiresAt = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
        const sessionData = {
          sessionId,
          familyId,
          uid,
          tenantId,
          clientId: client_id,
          ceremonyId: record.ceremonyId,
          status: 'pending_activation',
          redemptionLockId,
          fenceToken,
          deviceName: 'Web Client',
          browser: req.headers['user-agent'] ? String(req.headers['user-agent']).slice(0, 150) : 'Unknown Browser',
          ipAddress: req.ip || 'unknown',
          createdAt: now.toISOString(),
          lastSeenAt: now.toISOString(),
          expiresAt: expiresAt.toISOString(),
          revoked: false
        };

        const initialRefreshToken = generateRefreshToken(familyId, 1);
        const initialRefreshTokenHash = hashAuthorizationCode(initialRefreshToken);
        const familyData = {
          familyId,
          sessionId,
          uid,
          tenantId,
          clientId: client_id,
          ceremonyId: record.ceremonyId,
          status: 'pending_activation',
          redemptionLockId,
          fenceToken,
          currentActiveTokenHash: initialRefreshTokenHash,
          sequenceNumber: 1,
          rotatedTokenHashes: [],
          scope: record.scope || 'openid profile email',
          authTime: (record.userClaims && Number.isInteger(record.userClaims.authTime)) ? record.userClaims.authTime : null,
          expiresAt: expiresAt.toISOString(),
          createdAt: now.toISOString(),
          revoked: false
        };

        const sessionRef = db.collection('users').doc(uid).collection('sessions').doc(sessionId);
        const familyRef = db.collection('tenants').doc(tenantId).collection('token_families').doc(familyId);

        // 1. Mandatory create-only capability guard (Fail closed if unavailable)
        if (typeof sessionRef.create !== 'function' || typeof familyRef.create !== 'function') {
          console.error('[SECURITY ERROR] Firestore create-only capability is unavailable');
          await safeCleanup('missing_create_capability');
          return res.status(500).json({
            error: 'server_error',
            error_description: 'Firestore create-only capability is required for distributed staging.'
          });
        }

        // Stage pending session in Firestore using create-only semantics
        await sessionRef.create(sessionData);

        // Stage pending token family in Firestore using create-only semantics
        await familyRef.create(familyData);

        // 2. Fenced staged records pointer registration
        const regResult = await codeStore.registerStagedRecords({
          codeHash,
          redemptionLockId,
          fenceToken,
          uid,
          tenantId,
          clientId: client_id,
          ceremonyId: record.ceremonyId,
          issuedSessionId: sessionId,
          issuedFamilyId: familyId
        });

        if (!regResult.success) {
          await safeCleanup(`staged_registration_failed_${regResult.reason}`);
          return res.status(400).json({
            error: 'invalid_grant',
            error_description: `Redemption registration failed: ${regResult.reason}`
          });
        }

        // 3. Mint tokens via Scoped Compatibility Adapter (OIDC RS256 / Dual / Legacy Firebase)
        let tokensPayload;
        if (oidcTokenService && typeof oidcTokenService.buildTokenResponse === 'function') {
          tokensPayload = await oidcTokenService.buildTokenResponse({
            client: resolvedClient,
            uid,
            clientId: client_id,
            tenantId,
            sessionId,
            familyId,
            refreshToken: initialRefreshToken,
            scope: record.scope || 'openid profile email',
            userClaims: record.userClaims || {},
            nonce: record.nonce,
            authTime: record.userClaims ? record.userClaims.authTime : undefined,
            authAdmin
          });
        } else {
          const customToken = await authAdmin.createCustomToken(uid, {
            session_id: sessionId,
            tenant_id: tenantId,
            client_id
          });

          tokensPayload = {
            custom_token: customToken,
            refresh_token: initialRefreshToken,
            family_id: familyId,
            session_id: sessionId,
            expires_in: 3600
          };
        }

        // 4. Finalize redemption atomically
        const finalResult = await codeStore.finalizeRedemption({
          codeHash,
          redemptionLockId,
          fenceToken,
          uid,
          tenantId,
          issuedSessionId: sessionId,
          issuedFamilyId: familyId,
          rawTokensPayload: tokensPayload
        });

        if (!finalResult.success) {
          await safeCleanup(`finalization_failed_${finalResult.reason}`);
          return res.status(400).json({
            error: 'invalid_grant',
            error_description: `Redemption finalization failed: ${finalResult.reason}`
          });
        }

        return res.json(tokensPayload);
      } catch (innerErr) {
        console.error('[MINT/FINALIZATION ERROR] Triggering failure cleanup:', innerErr.message);
        await safeCleanup(innerErr.message);
        return res.status(500).json({ error: 'server_error', error_description: 'Token processing failed.' });
      }
    } catch (error) {
      console.error('[EXCHANGE ERROR]', error);
      return res.status(500).json({ error: 'server_error', error_description: error.message });
    }
  }

  router.post('/exchange', oauthExchangeLimiter, handleAuthorizationCodeGrant);

  /**
   * POST /token
   * Standards-Compliant OAuth 2.0 / OIDC Token Endpoint:
   * - grant_type=authorization_code: delegates to atomic two-phase code redemption & OIDC/compatibility adapter
   * - grant_type=refresh_token: enforces codeStore.authorizeRefreshGrant() before issuing rotated RS256/refresh tokens
   */
  router.post('/token', oauthExchangeLimiter, async (req, res) => {
    try {
      const { grant_type, refresh_token, family_id, session_id, uid, tenant_id } = req.body || {};
      if (grant_type === 'authorization_code') {
        return handleAuthorizationCodeGrant(req, res);
      }
      if (grant_type !== 'refresh_token') {
        return res.status(400).json({
          error: 'unsupported_grant_type',
          error_description: 'Only grant_type=authorization_code and grant_type=refresh_token are supported on /token.'
        });
      }
      if (
        typeof refresh_token !== 'string' || !refresh_token ||
        typeof family_id !== 'string' || !family_id ||
        typeof session_id !== 'string' || !session_id ||
        typeof uid !== 'string' || !uid
      ) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing required refresh_token parameters.'
        });
      }
      if (!codeStore || typeof codeStore.authorizeRefreshGrant !== 'function') {
        console.error('[SECURITY ERROR] Distributed codeStore refresh capability unavailable');
        return res.status(500).json({
          error: 'server_error',
          error_description: 'Distributed refresh authorization capability unavailable.'
        });
      }

      const tenantId = (typeof tenant_id === 'string' && tenant_id) ? tenant_id : 'lanzar';

      // Pre-authenticate confidential/disabled clients before mutating refresh token family when client_id is supplied
      if (req.body && req.body.client_id !== undefined && clientRegistryService) {
        const preClient = await resolveClientAsync(req.body.client_id);
        if (!preClient || !preClient.enabled) {
          return res.status(401).json({ error: 'invalid_client', error_description: 'Unknown or disabled client.' });
        }
        if (typeof clientRegistryService.verifyClientCredentials === 'function' &&
            !clientRegistryService.verifyClientCredentials(preClient, req.body.client_secret)) {
          return res.status(401).json({ error: 'invalid_client', error_description: 'Invalid client credentials.' });
        }
      }

      const authResult = await codeStore.authorizeRefreshGrant({
        tenantId,
        familyId: family_id,
        uid,
        sessionId: session_id,
        refreshToken: refresh_token,
        ...(req.body && req.body.client_id !== undefined ? { clientId: req.body.client_id } : {})
      });

      if (!authResult || authResult.allowed !== true) {
        return res.status(401).json({
          error: 'invalid_grant',
          error_description: 'Refresh token grant denied.',
          reason: authResult ? authResult.reason : 'AUTHORIZATION_DENIED',
          ...(authResult && authResult.replayDetected ? { replay_detected: true } : {})
        });
      }

      if (req.body && req.body.client_id !== undefined && authResult.clientId && req.body.client_id !== authResult.clientId) {
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Client identifier does not match token family.'
        });
      }

      const boundClient = authResult.clientId ? await resolveClientAsync(authResult.clientId) : null;
      if (clientRegistryService && authResult.clientId && !boundClient) {
        return res.status(401).json({ error: 'invalid_client', error_description: 'Unknown client.' });
      }
      if (boundClient && !boundClient.enabled) {
        return res.status(401).json({ error: 'invalid_client', error_description: 'Client is disabled.' });
      }
      if (boundClient && clientRegistryService && typeof clientRegistryService.verifyClientCredentials === 'function') {
        if (!clientRegistryService.verifyClientCredentials(boundClient, req.body && req.body.client_secret)) {
          return res.status(401).json({ error: 'invalid_client', error_description: 'Invalid client credentials.' });
        }
      }

      if (oidcTokenService && typeof oidcTokenService.mintAccessToken === 'function') {
        const grantedScope = normalizeScope(authResult.scope);
        const clientId = authResult.clientId || 'lanzar_client';
        const mode = (boundClient && boundClient.compatibilityMode) ? boundClient.compatibilityMode : 'legacy_firebase';

        const responseBody = {
          refresh_token: authResult.refreshToken,
          family_id: authResult.familyId,
          session_id: authResult.sessionId,
          sequence_number: authResult.sequenceNumber
        };

        if (mode === 'dual' || mode === 'oidc') {
          responseBody.access_token = await oidcTokenService.mintAccessToken({
            uid: authResult.uid || uid,
            clientId,
            tenantId: authResult.tenantId || tenantId,
            sessionId: authResult.sessionId,
            familyId: authResult.familyId,
            scope: grantedScope
          });
          responseBody.token_type = 'Bearer';
          responseBody.expires_in = ACCESS_TOKEN_TTL_SECONDS;
          responseBody.scope = grantedScope;
          if (hasScope(grantedScope, 'openid') && typeof oidcTokenService.mintIdToken === 'function') {
            responseBody.id_token = await oidcTokenService.mintIdToken({
              uid: authResult.uid || uid,
              clientId,
              tenantId: authResult.tenantId || tenantId,
              sessionId: authResult.sessionId,
              scope: grantedScope,
              authTime: authResult.authTime
            });
          }
        } else {
          responseBody.access_token = authResult.accessToken;
          responseBody.token_type = 'Bearer';
          responseBody.expires_in = 3600;
        }
        return res.status(200).json(responseBody);
      }

      return res.status(200).json({
        access_token: authResult.accessToken,
        token_type: 'Bearer',
        expires_in: 3600,
        refresh_token: authResult.refreshToken,
        family_id: authResult.familyId,
        session_id: authResult.sessionId,
        sequence_number: authResult.sequenceNumber
      });
    } catch (error) {
      console.error('[TOKEN REFRESH ERROR]', error);
      return res.status(500).json({ error: 'server_error', error_description: error.message });
    }
  });

  return router;
}

module.exports = { createOAuthRouter };
