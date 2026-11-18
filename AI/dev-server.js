/*
    dev-server.js

    Lightweight development server & API backend for LANZAR AI.

    Responsibilities:
    - Serve static files with correct MIME types and no-cache headers
    - Host authoritative /api/conversations REST API for Thread CRUD & Session Isolation
    - Enforce server-side user authentication & ownership verification
*/

const http = require('http');
const fs = require('fs');
const path = require('path');
const { conversationStore } = require('./server/conversation-store.js');
const { AuthVerifier } = require('./server/auth-verifier.js');
const { userProfileStore } = require('./server/user-profile-store.js');
const { userMemoryStore } = require('./server/user-memory-store.js');
const { hostedInferenceService } = require('./server/hosted-inference-service.js');
const { mathematicsService } = require('./server/mathematics-service.js');

const PORT = 5176;
const ROOT_DIR = __dirname;

const MIME_TYPES = {
  '.html': 'text/html; charset=UTF-8',
  '.js': 'application/javascript; charset=UTF-8',
  '.css': 'text/css; charset=UTF-8',
  '.json': 'application/json; charset=UTF-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.webmanifest': 'application/manifest+json; charset=UTF-8'
};

// =====================================
// Auth & Request Parsing Utilities
// =====================================

const ALLOWED_ORIGINS = new Set(
  (process.env.AI_ALLOWED_ORIGINS || `http://localhost:${PORT},http://127.0.0.1:${PORT},https://ai.lanzar.me,https://lanzar-ai-nova.netlify.app`)
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
);

const BLOCKED_STATIC_PREFIXES = ['/data/', '/server/', '/engine/', '/tests/', '/checkpoints/', '/.netlify/'];
const BLOCKED_STATIC_FILES = new Set(['package.json', 'package-lock.json', '.env', '.env.example', 'dev-server.js']);

const inferenceRateMap = new Map();
function checkInferenceRateLimit(key, maxPerMin = 30) {
  const now = Date.now();
  const rec = inferenceRateMap.get(key);
  if (!rec || now >= rec.resetAt) {
    inferenceRateMap.set(key, { count: 1, resetAt: now + 60000 });
    return true;
  }
  if (rec.count >= maxPerMin) return false;
  rec.count++;
  return true;
}

function resolveCorsOrigin(req) {
  const origin = req && req.headers ? req.headers.origin : null;
  if (origin && ALLOWED_ORIGINS.has(origin)) return origin;
  return `http://localhost:${PORT}`;
}

function sendJson(res, statusCode, data, req = null) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=UTF-8',
    'Access-Control-Allow-Origin': resolveCorsOrigin(req),
    'Vary': 'Origin',
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  });
  res.end(JSON.stringify(data));
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 2 * 1024 * 1024) { // 2MB limit
        reject(new Error('Payload too large'));
      }
    });
    req.on('end', () => {
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch (e) {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

// =====================================
// API Router (/api/conversations*, /api/auth*, /api/user*)
// =====================================

async function handleApiRequest(req, res, urlPath) {
  // Authoritative identity resolution
  let authUser;
  try {
    authUser = await AuthVerifier.verify(req.headers['authorization'], req.headers['x-user-id']);
  } catch (authErr) {
    return sendJson(res, 401, { error: authErr.message || 'Unauthorized' });
  }

  const userId = authUser.uid;
  const method = req.method;

  // Enforce authentication for private user data & inference routes
  const requiresAuth = (
    urlPath.startsWith('/api/memory') ||
    urlPath.startsWith('/api/conversations') ||
    urlPath.startsWith('/api/user') ||
    urlPath.startsWith('/api/inference/chat') ||
    urlPath.startsWith('/api/inference/multi') ||
    urlPath.startsWith('/api/inference/stream')
  );
  if (requiresAuth && !authUser.authenticated) {
    return sendJson(res, 401, { error: 'Authentication required' }, req);
  }

  if (urlPath.startsWith('/api/inference/') && urlPath !== '/api/inference/status') {
    const rlKey = `${authUser.uid}:${req.socket?.remoteAddress || 'local'}`;
    if (!checkInferenceRateLimit(rlKey)) {
      return sendJson(res, 429, { error: 'Rate limit exceeded. Please try again shortly.' }, req);
    }
  }

  // 0. Hosted AI Inference & Deterministic Math Endpoints
  if (urlPath === '/api/inference/status') {
    return sendJson(res, 200, hostedInferenceService.configSummary);
  }

  if (urlPath === '/api/math/verify' && method === 'POST') {
    const body = await readJsonBody(req);
    const result = mathematicsService.verifyMathematicalClaim(body);
    return sendJson(res, 200, result);
  }

  if (urlPath === '/api/inference/chat' && method === 'POST') {
    const body = await readJsonBody(req);
    try {
      const result = await hostedInferenceService.generateCompletion(body);
      return sendJson(res, 200, result);
    } catch (err) {
      return sendJson(res, 502, { error: err.message });
    }
  }

  if (urlPath === '/api/inference/multi-chat' && method === 'POST') {
    const body = await readJsonBody(req);
    try {
      const result = await hostedInferenceService.generateMultiCharacterCompletion(body);
      return sendJson(res, 200, result);
    } catch (err) {
      return sendJson(res, 502, { error: err.message });
    }
  }

  if (urlPath === '/api/inference/stream' && method === 'POST') {
    const body = await readJsonBody(req);
    hostedInferenceService.streamCompletion(body, res);
    return;
  }

  if (urlPath === '/api/inference/multi-stream' && method === 'POST') {
    const body = await readJsonBody(req);
    hostedInferenceService.streamMultiCharacterCompletion(body, res);
    return;
  }

  // 1. Auth Status Endpoint: /api/auth/me
  if (urlPath === '/api/auth/me') {
    const userData = userProfileStore.getUserData(userId, authUser);
    return sendJson(res, 200, {
      user: {
        uid: authUser.uid,
        email: authUser.email,
        displayName: authUser.displayName,
        photoURL: authUser.photoURL || '',
        authenticated: authUser.authenticated,
        isGuest: authUser.isGuest || false
      },
      profile: userData.profile,
      settings: userData.settings
    });
  }

  // 2. User Profile Endpoint: /api/user/profile
  if (urlPath === '/api/user/profile') {
    if (method === 'GET') {
      const userData = userProfileStore.getUserData(userId, authUser);
      return sendJson(res, 200, userData);
    }
    if (method === 'PATCH') {
      const body = await readJsonBody(req);
      const updatedProfile = userProfileStore.updateProfile(userId, body);
      return sendJson(res, 200, { profile: updatedProfile });
    }
    return sendJson(res, 405, { error: 'Method not allowed' });
  }

  // 3. User Settings Endpoint: /api/user/settings
  if (urlPath === '/api/user/settings') {
    if (method === 'GET') {
      const userData = userProfileStore.getUserData(userId, authUser);
      return sendJson(res, 200, userData.settings);
    }
    if (method === 'PATCH') {
      const body = await readJsonBody(req);
      const updatedSettings = userProfileStore.updateSettings(userId, body);
      return sendJson(res, 200, { settings: updatedSettings });
    }
    return sendJson(res, 405, { error: 'Method not allowed' });
  }

  // 4. User Long-Term Memory Endpoint: /api/user/memory
  if (urlPath === '/api/user/memory') {
    if (method === 'GET') {
      const memories = userMemoryStore.getMemories(userId);
      return sendJson(res, 200, { memories });
    }
    if (method === 'POST') {
      const body = await readJsonBody(req);
      const result = userMemoryStore.addMemory(userId, body);
      return sendJson(res, result.isUpdate ? 200 : 201, result);
    }
    return sendJson(res, 405, { error: 'Method not allowed' });
  }

  // 5. Relevant Memories for Character Context: /api/user/memory/relevant
  if (urlPath === '/api/user/memory/relevant') {
    if (method === 'GET') {
      const urlObj = new URL(req.url, `http://localhost:${PORT}`);
      const q = urlObj.searchParams.get('q') || '';
      const limit = parseInt(urlObj.searchParams.get('limit') || '5', 10);
      const relevant = userMemoryStore.getRelevantMemories(userId, q, limit);
      return sendJson(res, 200, { memories: relevant });
    }
    return sendJson(res, 405, { error: 'Method not allowed' });
  }

  // 6. Specific Memory CRUD: /api/user/memory/:id
  const memoryMatch = urlPath.match(/^\/api\/user\/memory\/([a-zA-Z0-9_-]+)$/);
  if (memoryMatch) {
    const memoryId = memoryMatch[1];
    if (method === 'GET') {
      const mem = userMemoryStore.getMemory(userId, memoryId);
      if (!mem) return sendJson(res, 404, { error: 'Memory not found' });
      return sendJson(res, 200, mem);
    }
    if (method === 'PATCH') {
      const body = await readJsonBody(req);
      const updated = userMemoryStore.updateMemory(userId, memoryId, body);
      if (!updated) return sendJson(res, 404, { error: 'Memory not found' });
      return sendJson(res, 200, { memory: updated });
    }
    if (method === 'DELETE') {
      const deleted = userMemoryStore.deleteMemory(userId, memoryId);
      if (!deleted) return sendJson(res, 404, { error: 'Memory not found' });
      return sendJson(res, 200, { success: true, deletedId: memoryId });
    }
    return sendJson(res, 405, { error: 'Method not allowed' });
  }

  // 7. List or Create: /api/conversations
  if (urlPath === '/api/conversations') {
    if (method === 'GET') {
      const list = conversationStore.list(userId);
      // If list is empty for default guest user, create initial seeded thread
      if (list.length === 0 && userId === 'user_default') {
        const initial = conversationStore.create(userId, {
          title: 'Rocket Engine Redesign',
          selectedPersonaId: 'auto'
        });
        // Seed welcome greeting
        conversationStore.addMessage(userId, initial.id, {
          role: 'assistant',
          content: "Welcome to LANZAR AI.\n\nBoth Penny (Possibility & Experimentation) and Pete (Analysis & Systems) are active in this workspace.\n\nAsk a question, propose an experiment, or bring a problem—we'll synthesize the best approach. What are we working on today?",
          persona: 'lanzar',
          authorName: 'LANZAR AI'
        });
        return sendJson(res, 200, conversationStore.list(userId));
      }
      return sendJson(res, 200, list);
    }
    if (method === 'POST') {
      const body = await readJsonBody(req);
      const newConv = conversationStore.create(userId, body);
      return sendJson(res, 201, newConv);
    }
    return sendJson(res, 405, { error: 'Method not allowed' });
  }

  // 3. Specific Conversation Actions: /api/conversations/:id...
  const convMatch = urlPath.match(/^\/api\/conversations\/([a-zA-Z0-9_-]+)(\/messages|\/history)?$/);
  if (convMatch) {
    const convId = convMatch[1];
    const subAction = convMatch[2]; // undefined | '/messages' | '/history'

    try {
      if (!subAction) {
        if (method === 'GET') {
          const conv = conversationStore.get(userId, convId);
          return sendJson(res, 200, conv);
        }
        if (method === 'PATCH') {
          const body = await readJsonBody(req);
          const updated = conversationStore.update(userId, convId, body);
          return sendJson(res, 200, updated);
        }
        if (method === 'DELETE') {
          conversationStore.delete(userId, convId);
          return sendJson(res, 200, { success: true, deletedId: convId });
        }
        return sendJson(res, 405, { error: 'Method not allowed' });
      }

      if (subAction === '/messages' && method === 'POST') {
        const body = await readJsonBody(req);
        const added = conversationStore.addMessage(userId, convId, body);
        return sendJson(res, 201, added);
      }

      if (subAction === '/history' && method === 'POST') {
        const body = await readJsonBody(req);
        const history = conversationStore.updateCommandHistory(userId, convId, body.history);
        return sendJson(res, 200, { success: true, history });
      }

      return sendJson(res, 404, { error: 'Endpoint not found' });
    } catch (err) {
      const status = err.status || (err.message.includes('denied') ? 403 : 500);
      return sendJson(res, status, { error: err.message });
    }
  }

  return sendJson(res, 404, { error: 'API route not found' });
}

// =====================================
// HTTP Server Main
// =====================================

const server = http.createServer(async (req, res) => {
  const urlPath = req.url.split('?')[0];

  // Handle CORS Preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(200, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-User-Id'
    });
    res.end();
    return;
  }

  // Route API Requests
  if (urlPath.startsWith('/api/')) {
    try {
      await handleApiRequest(req, res, urlPath);
    } catch (err) {
      console.error('[LANZAR AI API Error]', err);
      sendJson(res, 500, { error: err.message || 'Internal server error' });
    }
    return;
  }

  // Route Static Files (strictly block private data, server code, and env files)
  const normalizedUrl = urlPath.toLowerCase();
  const baseName = path.basename(normalizedUrl);
  if (
    BLOCKED_STATIC_PREFIXES.some(p => normalizedUrl.startsWith(p)) ||
    BLOCKED_STATIC_FILES.has(baseName) ||
    baseName.startsWith('.env')
  ) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('Forbidden');
    return;
  }

  let filePath = path.resolve(ROOT_DIR, (urlPath === '/' ? 'index.html' : urlPath).replace(/^\/+/, ''));

  // Prevent directory traversal
  if (filePath !== ROOT_DIR && !filePath.startsWith(ROOT_DIR + path.sep)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('Forbidden');
    return;
  }

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('404 Not Found');
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    res.writeHead(200, {
      'Content-Type': contentType,
      'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0',
      'Pragma': 'no-cache',
      'Expires': '0',
      'Access-Control-Allow-Origin': '*'
    });

    fs.createReadStream(filePath).pipe(res);
  });
});

server.listen(PORT, () => {
  console.log(`[LANZAR AI Dev Server] Listening at http://localhost:${PORT}/ (API + Static No-Cache Active)`);
});
