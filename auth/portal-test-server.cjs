// portal-test-server.js
// Minimal local test client representing LANZAR Portal (port 5173) for Phase F

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 5173;
const SDK_PATH = path.resolve(__dirname, 'src/sdk/lanzar-auth-modal.js');

const HTML_CONTENT = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>LANZAR Portal — Local Integration Client</title>
  <style>
    body {
      background: #0a0f1d;
      color: #e2e8f0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      margin: 0;
      padding: 40px;
    }
    .container {
      max-width: 720px;
      margin: 0 auto;
      background: #0f172a;
      border: 1px solid #1e293b;
      border-radius: 12px;
      padding: 32px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.5);
    }
    h1 { color: #38bdf8; margin-top: 0; font-size: 24px; }
    p { color: #94a3b8; font-size: 14px; line-height: 1.6; }
    .btn-group { display: flex; gap: 12px; margin: 24px 0; flex-wrap: wrap; }
    button {
      background: #0284c7;
      color: white;
      border: none;
      padding: 12px 20px;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.2s;
    }
    button:hover { background: #0369a1; }
    button.secondary { background: #334155; }
    button.secondary:hover { background: #475569; }
    #statusBox {
      background: #020617;
      border: 1px solid #334155;
      border-radius: 8px;
      padding: 16px;
      font-family: monospace;
      font-size: 13px;
      white-space: pre-wrap;
      word-break: break-all;
      min-height: 80px;
      color: #a5f3fc;
    }
    .badge {
      display: inline-block;
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 600;
      margin-bottom: 12px;
    }
    .badge.success { background: #065f46; color: #6ee7b7; }
    .badge.idle { background: #1e293b; color: #94a3b8; }
  </style>
  <script type="module" src="/sdk/lanzar-auth-modal.js"></script>
</head>
<body>
  <div class="container">
    <div id="statusBadge" class="badge idle">STATUS: CLIENT IDLE</div>
    <h1>LANZAR Mission Control (Test Portal)</h1>
    <p>This application exercises OAuth 2.0 / S256 PKCE integration with the local LANZAR ID Auth Hub (<code>http://localhost:4000</code>).</p>

    <div class="btn-group">
      <button id="btnModal">Open Auth Modal (iframe)</button>
      <button id="btnPopup" class="secondary">Open Auth Popup</button>
      <button id="btnRedirect" class="secondary">Top-Level Redirect</button>
      <button id="btnClear" class="secondary" style="background:#b91c1c;">Clear Session</button>
    </div>

    <h3>Client Handshake & Session Output:</h3>
    <div id="statusBox">Waiting for user interaction...</div>
  </div>

  <lanzar-auth-modal id="authModal"></lanzar-auth-modal>

  <script type="module">
    import { LanzarAuth, DEVELOPMENT_CONFIG } from '/sdk/lanzar-auth-modal.js';

    const modal = document.getElementById('authModal');
    const statusBox = document.getElementById('statusBox');
    const statusBadge = document.getElementById('statusBadge');

    function log(msg, isSuccess = false) {
      statusBox.textContent = typeof msg === 'string' ? msg : JSON.stringify(msg, null, 2);
      if (isSuccess) {
        statusBadge.className = 'badge success';
        statusBadge.textContent = 'STATUS: AUTHENTICATED';
      }
    }

    // Modal iframe setup
    modal._config = DEVELOPMENT_CONFIG;
    modal.addEventListener('lanzar:authenticated', async (e) => {
      const { code, state, codeVerifier } = e.detail;
      log('Received code from modal handshake!\\nCode: ' + code + '\\nVerifier: ' + codeVerifier + '\\nExchanging for token...');

      try {
        const session = await LanzarAuth.exchangeCodeForSession({
          code,
          clientId: 'portal',
          redirectUri: 'http://localhost:5173/',
          codeVerifier,
          authApiBase: 'http://localhost:4001'
        }, DEVELOPMENT_CONFIG);
        log({ message: 'PKCE exchange successful!', session }, true);
      } catch (err) {
        log('Exchange failed: ' + err.message);
      }
    });

    document.getElementById('btnModal').addEventListener('click', () => {
      modal.openWithPkce({
        clientId: 'portal',
        redirectUri: 'http://localhost:5173/'
      });
      log('Modal opened with local PKCE challenge. Awaiting login completion...');
    });

    // Popup flow
    document.getElementById('btnPopup').addEventListener('click', async () => {
      log('Launching popup authentication window...');
      try {
        const result = await LanzarAuth.openPopup({
          clientId: 'portal',
          redirectUri: 'http://localhost:5173/'
        }, DEVELOPMENT_CONFIG);

        log('Popup authenticated! Exchanging code with client-retained verifier: ' + result.codeVerifier);
        const session = await LanzarAuth.exchangeCodeForSession({
          code: result.code,
          clientId: 'portal',
          redirectUri: 'http://localhost:5173/',
          codeVerifier: result.codeVerifier,
          authApiBase: 'http://localhost:4001'
        }, DEVELOPMENT_CONFIG);
        log({ message: 'Popup PKCE exchange successful!', session }, true);
      } catch (err) {
        log('Popup flow error: ' + err.message);
      }
    });

    // Top-Level redirect flow
    document.getElementById('btnRedirect').addEventListener('click', async () => {
      const pkce = await LanzarAuth.generatePkcePair();
      sessionStorage.setItem('lanzar_pkce_verifier', pkce.codeVerifier);
      const url = LanzarAuth.buildAuthorizeUrl({
        clientId: 'portal',
        redirectUri: 'http://localhost:5173/',
        codeChallenge: pkce.codeChallenge,
        codeChallengeMethod: 'S256',
        state: 'redirect_test_' + Date.now()
      }, DEVELOPMENT_CONFIG);
      window.location.href = url;
    });

    // Check for incoming code in URL (top-level redirect callback)
    const params = new URLSearchParams(window.location.search);
    if (params.has('code')) {
      const code = params.get('code');
      const verifier = sessionStorage.getItem('lanzar_pkce_verifier');
      if (verifier) {
        log('Handling top-level redirect callback...\\nCode: ' + code + '\\nStored verifier: ' + verifier);
        LanzarAuth.exchangeCodeForSession({
          code,
          clientId: 'portal',
          redirectUri: 'http://localhost:5173/',
          codeVerifier: verifier,
          authApiBase: 'http://localhost:4001'
        }, DEVELOPMENT_CONFIG).then((session) => {
          sessionStorage.removeItem('lanzar_pkce_verifier');
          // Clear query params from URL
          window.history.replaceState({}, document.title, window.location.pathname);
          log({ message: 'Top-level redirect exchange successful!', session }, true);
        }).catch((err) => {
          log('Top-level exchange failed: ' + err.message);
        });
      }
    }

    document.getElementById('btnClear').addEventListener('click', () => {
      sessionStorage.clear();
      statusBadge.className = 'badge idle';
      statusBadge.textContent = 'STATUS: CLIENT IDLE';
      log('Client state cleared.');
    });
  </script>
</body>
</html>
`;

const server = http.createServer((req, res) => {
  const parsedUrl = new URL(req.url, `http://localhost:${PORT}`);
  
  if (parsedUrl.pathname === '/sdk/lanzar-auth-modal.js') {
    res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' });
    return fs.createReadStream(SDK_PATH).pipe(res);
  }

  // Default to index HTML
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(HTML_CONTENT);
});

server.listen(PORT, () => {
  console.log(`[PORTAL TEST CLIENT] Portal mock application listening on http://localhost:${PORT}`);
});
