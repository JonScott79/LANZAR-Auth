// originValidator.js
// Origin allowlisting and CORS header enforcement (LID-ARCH-REV-015 §2.3, §3.1, §3.2)

function createOriginMiddleware(config) {
  const originMap = config.originMap;

  return function originValidator(req, res, next) {
    const origin = req.headers.origin;

    // For OPTIONS preflight or normal requests
    if (origin) {
      const clientAppId = originMap[origin];
      if (!clientAppId) {
        return res.status(403).json({
          error: `Origin "${origin}" is not allowed in environment "${config.appEnv}"`,
          code: 'ORIGIN_NOT_ALLOWED'
        });
      }

      req.clientAppId = clientAppId;
      req.validatedOrigin = origin;

      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Lanzar-Client');
      res.setHeader('Vary', 'Origin');

      if (req.method === 'OPTIONS') {
        return res.status(204).end();
      }
    } else {
      // In development or test, non-browser requests without Origin (e.g. server-to-server or test runner)
      // may provide a test origin or client header, but protected web endpoints mandate Origin
      if (req.method === 'OPTIONS') {
        return res.status(400).json({ error: 'Origin header required for preflight', code: 'ORIGIN_REQUIRED' });
      }
    }

    next();
  };
}

function requireClientHeader(req, res, next) {
  const clientHeader = req.headers['x-lanzar-client'];
  if (clientHeader !== 'id') {
    return res.status(400).json({
      error: 'X-Lanzar-Client header must strictly be "id"',
      code: 'INVALID_CLIENT_HEADER'
    });
  }
  next();
}

module.exports = {
  createOriginMiddleware,
  requireClientHeader
};
