// app.js
// Express Application Factory for LANZAR ID (LID-ARCH-REV-015)

const express = require('express');
const { createOriginMiddleware } = require('./middleware/originValidator');
const { CookieService } = require('./services/cookieService');
const { CentralSessionService } = require('./services/centralSessionService');
const { createSessionRouter } = require('./routes/sessionRoutes');
const { createCommonVerifier } = require('./verifier/commonVerifier');
const { createPolicyMiddleware } = require('./verifier/policies');

function createApp({ config, db, authAdmin }) {
  const app = express();
  app.use(express.json());

  // Origin Validation & CORS Middleware (§2.3, §3.1)
  const originMiddleware = createOriginMiddleware(config);
  app.use(originMiddleware);

  // Initialize Services
  const cookieService = new CookieService(config);
  const centralSessionService = new CentralSessionService(db, authAdmin, config);
  const commonVerifier = createCommonVerifier(db, authAdmin, config);
  const policies = createPolicyMiddleware(commonVerifier, db);

  // Mount Central SSO & Session Routes (§4.2, §4.3)
  const sessionRouter = createSessionRouter({
    centralSessionService,
    cookieService,
    authAdmin,
    config
  });
  app.use('/api/id', sessionRouter);

  // Protected Demo / Reference Endpoints for Policy Verification (§5.2, §5.3, §5.4)
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

  // Healthcheck endpoint
  app.get('/api/id/health', (req, res) => {
    return res.status(200).json({
      status: 'healthy',
      appEnv: config.appEnv,
      nodeEnv: config.nodeEnv
    });
  });

  return {
    app,
    config,
    cookieService,
    centralSessionService,
    commonVerifier,
    policies
  };
}

module.exports = {
  createApp
};
