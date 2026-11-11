// test-mfa-qr-enrollment.cjs
// Verifies LANZAR ID MFA QR Code Enrollment backend, provisioning URI, pending TTL/replacement,
// encryption at rest, local QR SVG generation, and Login/MyLanzarAccount security hygiene.

const path = require('path');
const fs = require('fs');
const os = require('os');
const http = require('http');
const assert = require('assert');

module.paths.push(path.resolve(__dirname, 'auth-backend/node_modules'));
module.paths.push(path.resolve(__dirname, 'node_modules'));

if (process.env.APP_ENV === 'production' || process.env.NODE_ENV === 'production') {
  console.error('❌ [FATAL] Test suite must never execute against production environment.');
  process.exit(1);
}

process.env.APP_ENV = 'test';
process.env.NODE_ENV = 'test';

const express = require('express');
const mfaService = require('./auth-backend/mfaService');
const { createMfaRouter } = require('./auth-backend/routes/mfaRoutes');
const { MockFirestore } = require('./test-utils/mockFirebase.cjs');

let passed = 0;
let failed = 0;

function check(name, condition, detail = '') {
  if (condition) {
    console.log(`  ✓ ${name}${detail ? ` (${detail})` : ''}`);
    passed++;
  } else {
    console.error(`  ✗ ${name}${detail ? ` (${detail})` : ''}`);
    failed++;
  }
}

async function fetchJson(baseUrl, route, options = {}) {
  const res = await fetch(`${baseUrl}${route}`, {
    method: options.method || 'GET',
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    },
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  const data = await res.json().catch(() => ({}));
  return { status: res.status, data };
}

async function runTests() {
  console.log('========================================================');
  console.log('   LANZAR ID — MFA QR Code Enrollment Verification');
  console.log('========================================================\n');

  const db = new MockFirestore();
  const mockUsers = {
    'admin-uid-1': { uid: 'admin-uid-1', email: 'admin.test@lanzar.me', includeEmailInClaim: true },
    'admin-uid-2': { uid: 'admin-uid-2', email: 'fallback.admin@lanzar.me', includeEmailInClaim: false },
    'admin-uid-browser': { uid: 'admin-uid-browser', email: 'browser.admin@lanzar.me', includeEmailInClaim: true }
  };

  const authAdmin = {
    verifyIdToken: async (token) => {
      if (token === 'token-user-1') {
        return { uid: 'admin-uid-1', email: mockUsers['admin-uid-1'].email };
      }
      if (token === 'token-user-2-no-email-claim') {
        return { uid: 'admin-uid-2' };
      }
      if (token === 'token-user-browser') {
        return { uid: 'admin-uid-browser', email: mockUsers['admin-uid-browser'].email };
      }
      throw new Error('Invalid ID token');
    },
    getUser: async (uid) => mockUsers[uid] || null
  };

  const app = express();
  app.use(express.json());
  app.use('/mfa', createMfaRouter({
    db,
    authAdmin,
    isUserAdmin: async () => true
  }));

  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  // Capture console output to verify secrets / URIs are NEVER logged
  const capturedLogs = [];
  const origLog = console.log;
  const origWarn = console.warn;
  const origError = console.error;
  const hook = (fn) => (...args) => {
    capturedLogs.push(args.map(String).join(' '));
    return fn.apply(console, args);
  };

  try {
    console.log = hook(origLog);
    console.warn = hook(origWarn);
    console.error = hook(origError);

    // ---------------------------------------------------------
    // 1. Setup generates single secret + exact otpauth://totp/ URI
    // ---------------------------------------------------------
    origLog('[1] Testing /mfa/totp/setup response & Key URI specification...');
    const setup1 = await fetchJson(baseUrl, '/mfa/totp/setup', {
      method: 'POST',
      headers: { Authorization: 'Bearer token-user-1' },
      body: {}
    });

    check('Setup returns HTTP 200 and success=true', setup1.status === 200 && setup1.data.success === true);
    check('Setup returns Base32 secret', typeof setup1.data.secret === 'string' && /^[A-Z2-7]{16,}$/.test(setup1.data.secret));
    check('Setup returns otpauth://totp/ provisioning URI', typeof setup1.data.otpauthUrl === 'string' && setup1.data.otpauthUrl.startsWith('otpauth://totp/'));
    check('Setup response includes issuer LANZAR ID', setup1.data.issuer === 'LANZAR ID');
    check('Setup response includes user email account', setup1.data.account === 'admin.test@lanzar.me');
    check('Setup response includes SHA1 / 6 digits / 30s period', setup1.data.algorithm === 'SHA1' && setup1.data.digits === 6 && setup1.data.period === 30);

    const parsedUri1 = new URL(setup1.data.otpauthUrl);
    const decodedPath1 = decodeURIComponent(parsedUri1.pathname);
    check('URI label uses LANZAR ID:<email>', decodedPath1 === '/LANZAR ID:admin.test@lanzar.me', decodedPath1);
    check('URI encodes spaces with %20 instead of +', !setup1.data.otpauthUrl.includes('+'));
    check('URI secret matches response secret (single secret)', parsedUri1.searchParams.get('secret') === setup1.data.secret);
    check('URI issuer matches LANZAR ID', parsedUri1.searchParams.get('issuer') === 'LANZAR ID');
    check('URI algorithm is SHA1', parsedUri1.searchParams.get('algorithm') === 'SHA1');
    check('URI digits is 6', parsedUri1.searchParams.get('digits') === '6');
    check('URI period is 30', parsedUri1.searchParams.get('period') === '30');
    check('Pending cache holds exact same secret as URI', mfaService.getPendingEnrollment('admin-uid-1') === setup1.data.secret);

    // Email fallback lookup via authAdmin.getUser when claim omits email
    const setupEmailFallback = await fetchJson(baseUrl, '/mfa/totp/setup', {
      method: 'POST',
      headers: { Authorization: 'Bearer token-user-2-no-email-claim' },
      body: {}
    });
    const parsedFallback = new URL(setupEmailFallback.data.otpauthUrl);
    check('Email resolved via getUser fallback when missing from claim', decodeURIComponent(parsedFallback.pathname) === '/LANZAR ID:fallback.admin@lanzar.me');
    mfaService.clearPendingEnrollment('admin-uid-2');

    // ---------------------------------------------------------
    // 2. Reinitializing replaces/invalidates previous pending secret
    // ---------------------------------------------------------
    origLog('\n[2] Testing re-initialization invalidates previous pending secret...');
    const setup2 = await fetchJson(baseUrl, '/mfa/totp/setup', {
      method: 'POST',
      headers: { Authorization: 'Bearer token-user-1' },
      body: {}
    });

    check('Re-initialization generates a new distinct secret', setup2.status === 200 && setup2.data.secret !== setup1.data.secret);
    check('Pending enrollment now holds second secret', mfaService.getPendingEnrollment('admin-uid-1') === setup2.data.secret);

    const oldSecretCode = mfaService.generateTOTP(setup1.data.secret);
    const currentSecretCode = mfaService.generateTOTP(setup2.data.secret);
    // Guard against unlikely accidental collision
    if (oldSecretCode !== currentSecretCode) {
      const staleActivate = await fetchJson(baseUrl, '/mfa/totp/enable', {
        method: 'POST',
        headers: { Authorization: 'Bearer token-user-1' },
        body: { code: oldSecretCode }
      });
      check('Code from invalidated previous setup secret is rejected', staleActivate.status === 400 && staleActivate.data.error === 'invalid_code');
    } else {
      check('Code collision skipped cleanly', true);
    }

    // ---------------------------------------------------------
    // 3. Incorrect 6-digit codes are rejected without activating MFA
    // ---------------------------------------------------------
    origLog('\n[3] Testing incorrect TOTP codes do not enable MFA...');
    const wrongCode = currentSecretCode === '000000' ? '111111' : '000000';
    const badEnable = await fetchJson(baseUrl, '/mfa/totp/enable', {
      method: 'POST',
      headers: { Authorization: 'Bearer token-user-1' },
      body: { code: wrongCode }
    });
    check('Incorrect code rejected with 400 invalid_code', badEnable.status === 400 && badEnable.data.error === 'invalid_code');
    const mfaDocBefore = await db.collection('mfa_factors').doc('admin-uid-1').get();
    check('MFA remains disabled in Firestore after wrong code', !mfaDocBefore.exists);

    // ---------------------------------------------------------
    // 4. Expired enrollment attempt is rejected
    // ---------------------------------------------------------
    origLog('\n[4] Testing pending enrollment expiration enforcement...');
    const realDateNow = Date.now;
    try {
      Date.now = () => realDateNow() + (11 * 60 * 1000); // Advance 11 min past 10-min TTL
      const expiredEnable = await fetchJson(baseUrl, '/mfa/totp/enable', {
        method: 'POST',
        headers: { Authorization: 'Bearer token-user-1' },
        body: { code: currentSecretCode }
      });
      check('Expired pending enrollment rejected with 400 setup_expired', expiredEnable.status === 400 && expiredEnable.data.error === 'setup_expired');
    } finally {
      Date.now = realDateNow;
    }

    // Re-init after expiry (simulating user clicking Retry / Generate New QR Code)
    const setup3 = await fetchJson(baseUrl, '/mfa/totp/setup', {
      method: 'POST',
      headers: { Authorization: 'Bearer token-user-1' },
      body: {}
    });
    check('Fresh setup succeeds after expired enrollment', setup3.status === 200 && Boolean(setup3.data.otpauthUrl));

    // ---------------------------------------------------------
    // 5. Valid 6-digit code from scanned URI OR manual secret activates MFA + encrypts at rest
    // ---------------------------------------------------------
    origLog('\n[5] Testing valid TOTP activation from URI & manual secret + AES-256-GCM at rest...');
    const scannedSecret = new URL(setup3.data.otpauthUrl).searchParams.get('secret');
    assert.strictEqual(scannedSecret, setup3.data.secret);
    const manualCode = mfaService.generateTOTP(setup3.data.secret);
    const scannedCode = mfaService.generateTOTP(scannedSecret);
    check('Scanned URI secret produces identical 6-digit TOTP as manual secret', manualCode === scannedCode);

    const activateRes = await fetchJson(baseUrl, '/mfa/totp/enable', {
      method: 'POST',
      headers: { Authorization: 'Bearer token-user-1' },
      body: { code: scannedCode }
    });
    check('Valid TOTP activates MFA and returns 8 recovery codes', activateRes.status === 200 && activateRes.data.success === true && activateRes.data.recoveryCodes?.length === 8);
    check('Pending enrollment cleared immediately after activation', mfaService.getPendingEnrollment('admin-uid-1') === null);

    const storedDoc = (await db.collection('mfa_factors').doc('admin-uid-1').get()).data();
    check('Persisted TOTP secret is AES-256-GCM encrypted (no plaintext)', Boolean(storedDoc?.totpSecret?.encryptedSecret && storedDoc.totpSecret.iv && storedDoc.totpSecret.tag) && storedDoc.totpSecret.encryptedSecret !== setup3.data.secret);
    check('Decrypted stored secret equals enrolled secret', mfaService.decryptTotpSecret(storedDoc.totpSecret) === setup3.data.secret);

    // ---------------------------------------------------------
    // 6. Never log MFA secrets or provisioning URIs
    // ---------------------------------------------------------
    const joinedLogs = capturedLogs.join('\n');
    const leaked = [setup1.data.secret, setup2.data.secret, setup3.data.secret, setup1.data.otpauthUrl, setup3.data.otpauthUrl]
      .some((val) => joinedLogs.includes(val));
    check('Backend logs never contain MFA secrets or provisioning URIs', !leaked);

    // Restore console before Vite/UI checks
    console.log = origLog;
    console.warn = origWarn;
    console.error = origError;

    // ---------------------------------------------------------
    // 7. Static security audit: zero external QR APIs in frontend source
    // ---------------------------------------------------------
    origLog('\n[6] Auditing frontend source & local QR component...');
    const srcFiles = [
      path.resolve(__dirname, 'src/pages/Login.jsx'),
      path.resolve(__dirname, 'src/components/TotpQrCode.jsx'),
      path.resolve(__dirname, 'src/components/MyLanzarAccount.jsx')
    ];
    for (const filePath of srcFiles) {
      const content = fs.readFileSync(filePath, 'utf8');
      check(`${path.basename(filePath)} has zero external QR API references`, !content.includes('qrserver.com') && !content.includes('chart.googleapis.com'));
    }

    const loginSrc = fs.readFileSync(path.resolve(__dirname, 'src/pages/Login.jsx'), 'utf8');
    check('Login.jsx contains required QR instruction copy', loginSrc.includes('Scan this QR code with your authenticator app.'));
    check('Login.jsx uses local TotpQrCode component', loginSrc.includes('<TotpQrCode'));
    check('Login.jsx includes expandable manual fallback toggle & COPY KEY', loginSrc.includes('manual-setup-key-panel') && loginSrc.includes('aria-expanded={showManualKey}'));

    // ---------------------------------------------------------
    // 8. Local React + Vite + Chromium interactive UI verification
    // ---------------------------------------------------------
    origLog('\n[7] Running real headless Chromium UI verification of Login MFA QR flow...');
    const { createServer } = require('vite');
    const React = require('react');
    const { renderToStaticMarkup } = require('react-dom/server');
    const puppeteer = require('puppeteer');

    const mfaTestPlugin = {
      name: 'mfa-test-harness-plugin',
      resolveId(id) {
        if (id === '/__mfa_harness_entry.jsx') return '\0mfa-harness-entry.jsx';
      },
      load(id) {
        if (id === '\0mfa-harness-entry.jsx') {
          return `
            import React from 'react';
            import { createRoot } from 'react-dom/client';
            import './src/index.css';
            import './src/theme.css';
            import Login from './src/pages/Login.jsx';
            const mockUser = {
              uid: 'admin-uid-browser',
              email: 'browser.admin@lanzar.me',
              getIdToken: async () => 'token-user-browser'
            };
            createRoot(document.getElementById('test-root')).render(
              React.createElement(Login, {
                mfaChallenge: { required: true, enrollmentRequired: true, mfaSession: 'mfa_sess', user: mockUser }
              })
            );
          `;
        }
      }
    };

    const vite = await createServer({
      root: __dirname,
      logLevel: 'silent',
      plugins: [mfaTestPlugin],
      server: { host: '127.0.0.1', port: 0, strictPort: false, hmr: false }
    });
    await vite.listen();
    const viteAddress = vite.httpServer.address();
    const viteUrl = `http://127.0.0.1:${viteAddress.port}`;

    let browser;
    try {
      const mod = await vite.ssrLoadModule('/src/components/TotpQrCode.jsx');
      const TotpQrCode = mod.default;
      const svgMarkup = renderToStaticMarkup(
        React.createElement(TotpQrCode, { otpauthUrl: setup3.data.otpauthUrl, size: 184 })
      );
      check('TotpQrCode renders crisp local <svg> without external <img> requests', svgMarkup.includes('<svg') && svgMarkup.includes('<path') && !svgMarkup.includes('http://') && !svgMarkup.includes('https://'));

      const missingUriMarkup = renderToStaticMarkup(
        React.createElement(TotpQrCode, { otpauthUrl: null })
      );
      check('TotpQrCode fails safely (returns empty) on null URI', missingUriMarkup === '');

      // Interactive Browser E2E on Login.jsx against live Express mfaRoutes server
      await db.collection('mfa_factors').doc('admin-uid-browser').delete();

      const externalRequests = [];
      let simulateNextSetupFailure = true;

      browser = await puppeteer.launch({
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox']
      });
      const page = await browser.newPage();
      page.on('pageerror', (e) => origLog('  [PAGE ERROR]', e.message));
      page.on('requestfailed', (req) => origLog('  [REQ FAILED]', req.url(), req.failure()?.errorText));
      page.on('console', (msg) => {
        if (msg.type() === 'error') origLog('  [BROWSER CONSOLE ERROR]', msg.text());
      });
      await page.setViewport({ width: 520, height: 820 });
      await page.setRequestInterception(true);

      page.on('request', async (req) => {
        const reqUrl = req.url();
        if (reqUrl.startsWith(viteUrl)) {
          if (reqUrl.endsWith('/__mfa_test_harness__')) {
            const rawHtml = `<!doctype html><html><head></head><body style="background:#102a43;padding:24px;"><div id="test-root"></div><script type="module" src="/__mfa_harness_entry.jsx"></script></body></html>`;
            const html = await vite.transformIndexHtml('/__mfa_test_harness__', rawHtml);
            return req.respond({
              status: 200,
              contentType: 'text/html',
              body: html
            });
          }
          return req.continue();
        }
        if (reqUrl.includes('/mfa/totp/')) {
          if (req.method() === 'OPTIONS') {
            return req.respond({
              status: 204,
              headers: {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type, Authorization',
                'Access-Control-Allow-Methods': 'POST, OPTIONS'
              }
            });
          }
          if (reqUrl.endsWith('/mfa/totp/setup') && simulateNextSetupFailure) {
            simulateNextSetupFailure = false;
            return req.respond({
              status: 503,
              contentType: 'application/json',
              headers: { 'Access-Control-Allow-Origin': '*' },
              body: JSON.stringify({ error: 'service_unavailable', error_description: 'Simulated setup outage' })
            });
          }
          const target = reqUrl.replace(/^https?:\/\/[^/]+/, baseUrl);
          const upstream = await fetch(target, {
            method: req.method(),
            headers: req.headers(),
            body: req.postData()
          });
          const text = await upstream.text();
          return req.respond({
            status: upstream.status,
            contentType: 'application/json',
            headers: { 'Access-Control-Allow-Origin': '*' },
            body: text
          });
        }
        externalRequests.push(reqUrl);
        return req.abort();
      });

      await page.goto(`${viteUrl}/__mfa_test_harness__`, { waitUntil: 'domcontentloaded' });

      // Step A: First auto-init fails with 503 -> verify error + RETRY SETUP button (no stuck spinner!)
      await page.waitForSelector('button.primary-btn', { timeout: 8000 });
      const retryText = await page.$eval('button.primary-btn', (el) => el.textContent.trim());
      check('Init failure displays RETRY SETUP button instead of hanging', retryText === 'RETRY SETUP', retryText);

      // Step B: Click RETRY SETUP -> loads local QR SVG automatically
      await page.click('button.primary-btn');
      await page.waitForSelector('.qr-code-frame svg');
      const uiState = await page.evaluate(() => ({
        instruction: document.querySelector('.qr-instruction')?.textContent?.trim(),
        hasSvg: Boolean(document.querySelector('.qr-code-frame svg path')),
        hasImgInQr: Boolean(document.querySelector('.qr-code-frame img')),
        manualHiddenInitially: !document.getElementById('manual-setup-key-panel')
      }));
      check('UI renders instruction "Scan this QR code with your authenticator app."', uiState.instruction === 'Scan this QR code with your authenticator app.');
      check('UI renders local SVG QR code with zero <img> tags', uiState.hasSvg && !uiState.hasImgInQr);
      check('Manual setup key is collapsed initially behind toggle', uiState.manualHiddenInitially);

      // Verify real rendered page dimensions / SVG paint via screenshot into OS temp dir
      const previewPath = path.join(os.tmpdir(), `lanzar-mfa-qr-${Date.now()}.png`);
      await page.screenshot({ path: previewPath, fullPage: true });
      check('Rendered QR UI screenshot captured cleanly', fs.existsSync(previewPath) && fs.statSync(previewPath).size > 1000);
      fs.unlinkSync(previewPath);

      // Step C: Expand manual setup key fallback & verify secret matches backend pending secret
      await page.click('.manual-key-toggle');
      await page.waitForSelector('#manual-setup-key-panel .secret-code');
      const displayedSecret = await page.$eval('#manual-setup-key-panel .secret-code', (el) => el.textContent.trim());
      const backendPendingSecret = mfaService.getPendingEnrollment('admin-uid-browser');
      check('Expandable manual fallback displays exact pending backend secret', displayedSecret === backendPendingSecret);

      // Step D: Submit wrong 6-digit code -> displays error & keeps enrollment open
      await page.type('#mfa-verify-code', '999999');
      await page.click('button[type="submit"]');
      await page.waitForSelector('.error-msg');
      const errText = await page.$eval('.error-msg', (el) => el.textContent.trim());
      check('Incorrect 6-digit code in browser shows verification error', errText.toLowerCase().includes('incorrect'));

      // Step E: Click "Generate new QR code" -> verifies secret rotates cleanly in UI
      await Promise.all([
        page.waitForResponse((res) => res.url().includes('/mfa/totp/setup') && res.request().method() === 'POST' && res.status() === 200),
        page.click('.mfa-secondary-actions button.text-link')
      ]);
      await page.waitForSelector('.qr-code-frame svg');
      const rotatedPendingSecret = mfaService.getPendingEnrollment('admin-uid-browser');
      check('Clicking "Generate new QR code" rotates pending secret in UI & backend', Boolean(rotatedPendingSecret) && rotatedPendingSecret !== backendPendingSecret);

      // Step F: Generate valid 6-digit code for rotated secret & activate MFA in browser
      const liveValidCode = mfaService.generateTOTP(rotatedPendingSecret);
      await page.click('#mfa-verify-code');
      await page.keyboard.down('Control');
      await page.keyboard.press('A');
      await page.keyboard.up('Control');
      await page.keyboard.press('Backspace');
      await page.type('#mfa-verify-code', liveValidCode);
      await page.click('button[type="submit"]');
      await page.waitForSelector('.recovery-code-grid', { timeout: 8000 });
      const recCount = await page.$$eval('.recovery-code-pill', (els) => els.length);
      check('Valid 6-digit code activates MFA in UI and displays 8 recovery codes', recCount === 8);
      check('Zero external requests made during entire browser QR enrollment flow', externalRequests.length === 0, `externalRequests=${externalRequests.length}`);
    } finally {
      if (browser) await browser.close();
      await vite.close();
    }

    console.log('\n========================================================');
    console.log(`   MFA QR ENROLLMENT RESULTS: ${passed} PASSED, ${failed} FAILED`);
    console.log('========================================================');
    if (failed > 0) process.exit(1);
  } finally {
    console.log = origLog;
    console.warn = origWarn;
    console.error = origError;
    server.close();
  }
}

runTests().then(() => process.exit(0)).catch((err) => {
  console.error('❌ Test runner error:', err);
  process.exit(1);
});
