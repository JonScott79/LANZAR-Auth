// app.js
// Universal Express Application Factory for LANZAR ID (Phase 1 & Phase 2 Ecosystem)

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

const { createAccountRouter } = require('./routes/accountRoutes');
const { createMfaRouter } = require('./routes/mfaRoutes');
const { createOAuthRouter } = require('./routes/oauthRoutes');
const { createProfileRouter } = require('./routes/profileRoutes');
const { createDeviceSessionRouter } = require('./routes/deviceSessionRoutes');
const { createPhoneRouter } = require('./routes/phoneRoutes');
const { createDispatchRouter } = require('./routes/dispatchRoutes');
const { createAdminRouter } = require('./routes/adminRoutes');
const { createSessionRouter } = require('./routes/sessionRoutes');

function createApp({ config, db, authAdmin, services = {}, stores = {} }) {
  const app = express();

  // Trusted Reverse Proxy Configuration (LID-VER-003)
  const trustProxySetting = config?.trustProxy || process.env.TRUST_PROXY || 'loopback, linklocal, uniquelocal';
  app.set('trust proxy', trustProxySetting);

  app.use(express.json());

  // CORS and Origin Validation
  if (config && config.originMap) {
    const originMiddleware = createOriginMiddleware(config);
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

  const oauthRouter = createOAuthRouter({
    db,
    authAdmin,
    codeStore,
    sessionService,
    isUserAdmin: authMiddleware.isUserAdmin,
    reconcileCustomerAccount
  });
  app.use('/', oauthRouter);

  const profileRouter = createProfileRouter({
    profileService,
    authenticateUserMiddleware: authMiddleware.authenticateUserMiddleware
  });
  app.use('/api/id', profileRouter);

  const deviceSessionRouter = createDeviceSessionRouter({
    db,
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

  const adminRouter = createAdminRouter({
    db,
    profileService,
    founderService,
    sessionService,
    authenticateAdminMiddleware: authMiddleware.authenticateAdminMiddleware
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
    authMiddleware
  };
}

module.exports = {
  createApp
};
