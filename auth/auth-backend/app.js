// app.js
// Universal Express Application Factory for LANZAR ID (Phase 1 & Phase 2 Ecosystem)

const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const { createOriginMiddleware } = require('./middleware/originValidator');
const { createAuthMiddleware } = require('./middleware/authMiddleware');
const { CookieService } = require('./services/cookieService');
const { CentralSessionService } = require('./services/centralSessionService');
const { createCommonVerifier } = require('./verifier/commonVerifier');
const { createPolicyMiddleware } = require('./verifier/policies');

const { SessionService } = require('./sessionService');
const { FounderService } = require('./founderService');
const { ProfileService } = require('./profileService');
const { SMSService } = require('./smsService');
const { AuthorizationCodeStore, FirestoreAuthorizationCodeStore } = require('./store');
const { SigningKeystore } = require('./services/signingKeystore');
const { OidcTokenService } = require('./services/oidcTokenService');
const { ClientRegistryService } = require('./services/clientRegistryService');
const { TenantService } = require('./services/tenantService');
const { BillingService } = require('./services/billingService');
const { AuditLogService } = require('./services/auditLogService');
const { PlatformOutboxService } = require('./services/platformOutboxService');

const { createAccountRouter } = require('./routes/accountRoutes');
const { createMfaRouter } = require('./routes/mfaRoutes');
const { createOAuthRouter } = require('./routes/oauthRoutes');
const { createJwksRouter } = require('./routes/jwksRoutes');
const { createOidcRouter } = require('./routes/oidcRoutes');
const { createClientRegistryRouter } = require('./routes/clientRegistryRoutes');
const { createProfileRouter } = require('./routes/profileRoutes');
const { createDeviceSessionRouter } = require('./routes/deviceSessionRoutes');
const { createPhoneRouter } = require('./routes/phoneRoutes');
const { createDispatchRouter } = require('./routes/dispatchRoutes');
const { createAdminRouter } = require('./routes/adminRoutes');
const { createSessionRouter } = require('./routes/sessionRoutes');
const { createDeveloperRouter } = require('./routes/developerRoutes');
const { createBillingWebhookRouter, attachTenantBillingRoutes } = require('./routes/billingRoutes');

function createApp({ config, db, authAdmin, services = {}, stores = {} }) {
  const app = express();

  // Express Reverse-Proxy Configuration:
  // Do NOT blindly set 'trust proxy' to true, 1, or guessed Railway proxy subnets.
  // Railway does not publish stable proxy source ranges or a fixed hop-count contract.
  // By default, keep Express trust proxy disabled (false) to avoid trusting arbitrary forwarding headers.
  // Rate limiting and client IP resolution are handled authoritatively via X-Real-IP in getClientIp().
  const trustProxySetting = config?.trustProxy !== undefined
    ? config.trustProxy
    : (process.env.TRUST_PROXY !== undefined ? process.env.TRUST_PROXY : false);
  app.set('trust proxy', trustProxySetting);

  const tenantService = services.tenantService || (
    db && typeof db.collection === 'function'
      ? new TenantService(db)
      : null
  );

  const billingService = services.billingService || (
    db && typeof db.collection === 'function' && tenantService
      ? new BillingService(db, tenantService)
      : null
  );

  // Stripe Webhook Receiver (must be mounted BEFORE express.json() for raw body signature verification)
  if (billingService) {
    app.use('/api/billing', createBillingWebhookRouter({ billingService }));
  }

  app.use(express.json());

  // Correlation / Request ID Propagation
  app.use((req, res, next) => {
    const incomingId = req.headers['x-correlation-id'] || req.headers['x-request-id'];
    const correlationId = (typeof incomingId === 'string' && incomingId.trim())
      ? incomingId.trim().slice(0, 128)
      : crypto.randomUUID();
    req.correlationId = correlationId;
    res.setHeader('X-Correlation-ID', correlationId);
    next();
  });

  const clientRegistryService = services.clientRegistryService || (
    db && typeof db.collection === 'function'
      ? new ClientRegistryService(db)
      : null
  );

  // CORS and Origin Validation (supports dynamic registered client origins on OAuth/OIDC/session paths)
  if (config && config.originMap) {
    const originMiddleware = createOriginMiddleware(config, { clientRegistryService });
    app.use(originMiddleware);
  } else {
    app.use(cors());
  }

  // Domain Services Initialization (Injected or Defaulted)
  const sessionService = services.sessionService || new SessionService(db, authAdmin);
  const founderService = services.founderService || new FounderService(db);
  const profileService = services.profileService || new ProfileService(db, authAdmin, sessionService);
  const smsService = services.smsService || new SMSService(db);
  const codeStore = stores.codeStore || (db && typeof db.collection === 'function'
    ? new FirestoreAuthorizationCodeStore(db)
    : new AuthorizationCodeStore());
  const signingKeystore = services.signingKeystore || (db && typeof db.collection === 'function'
    ? new SigningKeystore(db)
    : null);

  // Phase 1 Central SSO Services (When config provided)
  let cookieService = null;
  let centralSessionService = null;
  let commonVerifier = null;
  let policies = null;

  if (config) {
    cookieService = new CookieService(config);
    centralSessionService = new CentralSessionService(db, authAdmin, config);
    commonVerifier = createCommonVerifier(db, authAdmin, config);
    policies = createPolicyMiddleware(commonVerifier, db);
  }

  // Shared Authentication Middleware
  const authMiddleware = createAuthMiddleware({
    db,
    authAdmin,
    sessionService
  });

  // Mount Modular Routers
  const { router: accountRouter, reconcileCustomerAccount } = createAccountRouter({ db, authAdmin });
  app.use('/', accountRouter);

  const mfaRouter = createMfaRouter({
    db,
    authAdmin,
    isUserAdmin: authMiddleware.isUserAdmin
  });
  app.use('/mfa', mfaRouter);

  const resolvedIssuer = (config && config.oidcIssuer) || process.env.OIDC_ISSUER || (config ? config.apiBaseUrl : undefined);
  const resolvedApiBaseUrl = (config && config.apiBaseUrl) || undefined;
  const oidcTokenService = services.oidcTokenService || (
    signingKeystore
      ? new OidcTokenService({ signingKeystore, issuer: resolvedIssuer, apiBaseUrl: resolvedApiBaseUrl })
      : null
  );

  const oauthRouter = createOAuthRouter({
    db,
    authAdmin,
    codeStore,
    sessionService,
    isUserAdmin: authMiddleware.isUserAdmin,
    reconcileCustomerAccount,
    oidcTokenService,
    clientRegistryService,
    tenantService,
    authHubUrl: config ? config.authHubUrl : undefined
  });
  app.use('/oauth', oauthRouter);
  app.use('/', oauthRouter);

  const auditLogService = services.auditLogService || (
    db && typeof db.collection === 'function'
      ? new AuditLogService(db)
      : null
  );

  if (tenantService && clientRegistryService) {
    const developerRouter = createDeveloperRouter({
      tenantService,
      clientRegistryService,
      auditLogService,
      oidcTokenService,
      authenticateUserMiddleware: authMiddleware.authenticateUserMiddleware
    });
    if (billingService) {
      attachTenantBillingRoutes(developerRouter, { tenantService, clientRegistryService, billingService });
    }
    app.use('/api/dev', developerRouter);
  }

  const clientRegistryRouter = createClientRegistryRouter({
    clientRegistryService,
    authenticateAdminMiddleware: authMiddleware.authenticateAdminMiddleware,
    auditLogService
  });
  app.use('/api/admin/id', clientRegistryRouter);

  const jwksRouter = createJwksRouter({ signingKeystore });
  app.use('/', jwksRouter);

  const oidcRouter = createOidcRouter({ oidcTokenService, db, clientRegistryService });
  app.use('/', oidcRouter);

  const profileRouter = createProfileRouter({
    profileService,
    authenticateUserMiddleware: authMiddleware.authenticateUserMiddleware
  });
  app.use('/api/id', profileRouter);

  const deviceSessionRouter = createDeviceSessionRouter({
    db,
    authAdmin,
    sessionService,
    authenticateUserMiddleware: authMiddleware.authenticateUserMiddleware,
    isUserAdmin: authMiddleware.isUserAdmin
  });
  app.use('/api/id', deviceSessionRouter);

  const phoneRouter = createPhoneRouter({
    smsService,
    authenticateUserMiddleware: authMiddleware.authenticateUserMiddleware
  });
  app.use('/api/id/phone', phoneRouter);

  const dispatchRouter = createDispatchRouter({
    db,
    authenticateUserMiddleware: authMiddleware.authenticateUserMiddleware
  });
  app.use('/api/id/dispatch', dispatchRouter);

  const platformOutboxService = services.platformOutboxService || (
    db && typeof db.collection === 'function'
      ? new PlatformOutboxService(db, authAdmin, { auditLogService })
      : null
  );

  const adminRouter = createAdminRouter({
    db,
    authAdmin,
    profileService,
    founderService,
    sessionService,
    authenticateAdminMiddleware: authMiddleware.authenticateAdminMiddleware,
    auditLogService,
    platformOutboxService
  });
  app.use('/api/admin/id', adminRouter);

  // Mount Phase 1 Central SSO Routes
  if (centralSessionService && cookieService) {
    const sessionRouter = createSessionRouter({
      centralSessionService,
      cookieService,
      authAdmin,
      config
    });
    app.use('/api/id', sessionRouter);
  }

  // Protected Demo / Reference Endpoints for Policy Verification (§5.2, §5.3, §5.4)
  if (policies) {
    app.get('/api/id/portal/summary', policies.enforcePolicyA, (req, res) => {
      return res.status(200).json({
        message: 'Policy A Access Granted',
        authContext: req.authContext
      });
    });

    app.get('/api/pythos/data', policies.enforcePolicyB('pythos'), (req, res) => {
      return res.status(200).json({
        message: 'Policy B Pythos Access Granted',
        authContext: req.authContext
      });
    });

    app.get('/api/tickets/queue', policies.enforcePolicyB('tickets'), (req, res) => {
      return res.status(200).json({
        message: 'Policy B Tickets Access Granted',
        authContext: req.authContext
      });
    });

    app.get('/api/threadline/feed', policies.enforcePolicyB('threadline'), (req, res) => {
      return res.status(200).json({
        message: 'Policy B Threadline Access Granted',
        authContext: req.authContext
      });
    });

    app.get('/api/admin/system-status', policies.enforcePolicyC(), (req, res) => {
      return res.status(200).json({
        message: 'Policy C Mission Control Access Granted',
        authContext: req.authContext,
        adminProfile: req.adminProfile
      });
    });

    app.get('/api/admin/users/export', policies.enforcePolicyC('users:export'), (req, res) => {
      return res.status(200).json({
        message: 'Policy C Scoped Permission Access Granted',
        permission: 'users:export'
      });
    });
  }

  // Healthcheck endpoint
  app.get('/api/id/health', (req, res) => {
    return res.status(200).json({
      status: 'healthy',
      appEnv: config?.appEnv || 'development',
      nodeEnv: config?.nodeEnv || process.env.NODE_ENV || 'development'
    });
  });

  // Readiness endpoint (verifies Firestore connectivity & signing key availability without leaking secrets)
  app.get('/api/id/ready', async (req, res) => {
    const checks = { firestore: 'unavailable', signingKeystore: 'unavailable' };
    try {
      if (!db || typeof db.collection !== 'function') {
        return res.status(503).json({ status: 'not_ready', checks, correlationId: req.correlationId });
      }
      await db.collection('system_signing_keys').doc('_active_pointer').get();
      checks.firestore = 'ok';

      if (!signingKeystore || typeof signingKeystore.getPublicJwks !== 'function') {
        return res.status(503).json({ status: 'not_ready', checks, correlationId: req.correlationId });
      }
      const jwks = await signingKeystore.getPublicJwks({ bypassCache: true });
      const keyCount = Array.isArray(jwks && jwks.keys) ? jwks.keys.length : 0;
      if (keyCount === 0) {
        return res.status(503).json({ status: 'not_ready', checks: { ...checks, signingKeystore: 'no_active_keys' }, correlationId: req.correlationId });
      }
      checks.signingKeystore = 'ok';
      return res.status(200).json({ status: 'ready', checks, keyCount, correlationId: req.correlationId });
    } catch (err) {
      console.error('[READINESS ERROR]', { correlationId: req.correlationId, message: err.message });
      return res.status(503).json({ status: 'not_ready', checks, correlationId: req.correlationId });
    }
  });

  // Sanitized terminal error handler (never leaks secrets or stack traces)
  app.use((err, req, res, next) => {
    console.error('[UNHANDLED ERROR]', { correlationId: req.correlationId, message: err && err.message ? err.message : 'Unknown error' });
    if (res.headersSent) return next(err);
    return res.status(500).json({
      error: 'server_error',
      error_description: 'An internal error occurred.',
      correlationId: req.correlationId
    });
  });

  return {
    app,
    config,
    cookieService,
    centralSessionService,
    commonVerifier,
    policies,
    sessionService,
    founderService,
    profileService,
    smsService,
    codeStore,
    signingKeystore,
    authMiddleware,
    platformOutboxService
  };
}

module.exports = {
  createApp
};
