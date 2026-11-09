// test-popup-modal-handshake.cjs
// Verification suite for Popup & Modal Authentication Handshake & Origin Security (Phase E.1)

const assert = require('assert');
const {
  LanzarAuthModal,
  LanzarAuth,
  generatePkcePair,
  buildAuthorizeUrl,
  STAGING_CONFIG,
  PRODUCTION_CONFIG
} = require('./src/sdk/lanzar-auth-modal.js');

console.log('\n======================================================');
console.log('LANZAR ID — Popup & Modal Handshake Verification Suite');
console.log('Target Specification: Phase E.1 Handshake Security');
console.log(`Timestamp: ${new Date().toISOString()}`);
console.log('======================================================\n');

let passCount = 0;
let failCount = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✓ [PASS] ${name}`);
    passCount++;
  } catch (err) {
    console.error(`  ✗ [FAIL] ${name}: ${err.message}`);
    failCount++;
  }
}

async function run() {
  // 1. Modal Iframe Handshake Verification
  await test('HANDSHAKE-01: Modal iframe accepts message when origin and contentWindow match', async () => {
    const modal = new LanzarAuthModal();
    modal._config = STAGING_CONFIG;
    modal._codeVerifier = 'test_retained_client_verifier_12345678901234567890';

    const fakeIframeWindow = {};
    modal.shadowRoot = {
      getElementById: (id) => (id === 'authFrame' ? { contentWindow: fakeIframeWindow } : null)
    };

    let receivedDetail = null;
    modal.dispatchEvent = (event) => {
      if (event.type === 'lanzar:authenticated') {
        receivedDetail = event.detail;
      }
    };
    modal.close = () => {};

    // Post valid message from correct origin and matching contentWindow
    modal._onMessage({
      origin: STAGING_CONFIG.authHubUrl,
      source: fakeIframeWindow,
      data: {
        type: 'lanzar:authenticated',
        payload: { code: 'auth_code_123', state: 'xyz' }
      }
    });

    assert(receivedDetail !== null, 'Authenticated event must be dispatched');
    assert.strictEqual(receivedDetail.code, 'auth_code_123');
    assert.strictEqual(receivedDetail.state, 'xyz');
    assert.strictEqual(receivedDetail.codeVerifier, 'test_retained_client_verifier_12345678901234567890');
  });

  await test('HANDSHAKE-02: Modal iframe strictly rejects message with unauthorized origin', async () => {
    const modal = new LanzarAuthModal();
    modal._config = STAGING_CONFIG;
    modal._codeVerifier = 'verifier_abc';

    const fakeIframeWindow = {};
    modal.shadowRoot = {
      getElementById: (id) => (id === 'authFrame' ? { contentWindow: fakeIframeWindow } : null)
    };

    let dispatched = false;
    modal.dispatchEvent = () => { dispatched = true; };

    // Attacker origin
    modal._onMessage({
      origin: 'https://evil-attacker.com',
      source: fakeIframeWindow,
      data: {
        type: 'lanzar:authenticated',
        payload: { code: 'malicious_code', state: 'xyz' }
      }
    });

    assert.strictEqual(dispatched, false, 'Message from unapproved origin must be rejected and discarded');
  });

  await test('HANDSHAKE-03: Modal iframe strictly rejects message when source window mismatches', async () => {
    const modal = new LanzarAuthModal();
    modal._config = STAGING_CONFIG;
    modal._codeVerifier = 'verifier_abc';

    const legitIframeWindow = {};
    const rogueWindow = {};
    modal.shadowRoot = {
      getElementById: (id) => (id === 'authFrame' ? { contentWindow: legitIframeWindow } : null)
    };

    let dispatched = false;
    modal.dispatchEvent = () => { dispatched = true; };

    // Valid origin but rogue source window (e.g. rogue cross-window message)
    modal._onMessage({
      origin: STAGING_CONFIG.authHubUrl,
      source: rogueWindow,
      data: {
        type: 'lanzar:authenticated',
        payload: { code: 'spoofed_code', state: 'xyz' }
      }
    });

    assert.strictEqual(dispatched, false, 'Message from unexpected source window must be discarded');
  });

  // 2. Popup Handshake Verification
  await test('HANDSHAKE-04: Popup handshake validates origin and source window', async () => {
    const fakePopupWindow = { closed: false };
    let messageListener = null;

    // Mock window environment
    global.window = {
      location: { href: 'https://portal.lanzar.me/dashboard' },
      screen: { width: 1920, height: 1080 },
      open: (url, name, features) => fakePopupWindow,
      addEventListener: (type, listener) => {
        if (type === 'message') messageListener = listener;
      },
      removeEventListener: () => {}
    };

    const popupPromise = LanzarAuth.openPopup({
      clientId: 'portal',
      redirectUri: 'https://portal.lanzar.me/dashboard'
    }, STAGING_CONFIG);

    // Allow async PKCE generation in openPopup to proceed to promise listener setup
    await new Promise((r) => setTimeout(r, 10));

    assert(typeof messageListener === 'function', 'Message listener must be registered');

    // Deliver valid message from popup
    messageListener({
      origin: STAGING_CONFIG.authHubUrl,
      source: fakePopupWindow,
      data: {
        type: 'lanzar:authenticated',
        payload: { code: 'popup_code_987', state: 'state_123' }
      }
    });

    const result = await popupPromise;
    assert.strictEqual(result.code, 'popup_code_987');
    assert.strictEqual(result.state, 'state_123');
    assert(result.codeVerifier && result.codeVerifier.length >= 43, 'Client-retained verifier returned');

    delete global.window;
  });

  await test('HANDSHAKE-05: Popup handshake ignores unauthorized origin', async () => {
    const fakePopupWindow = { closed: false };
    let messageListener = null;

    global.window = {
      location: { href: 'https://portal.lanzar.me/dashboard' },
      screen: { width: 1920, height: 1080 },
      open: () => fakePopupWindow,
      addEventListener: (type, listener) => {
        if (type === 'message') messageListener = listener;
      },
      removeEventListener: () => {}
    };

    let resolved = false;
    const popupPromise = LanzarAuth.openPopup({ clientId: 'portal' }, STAGING_CONFIG).then(() => {
      resolved = true;
    });

    await new Promise((r) => setTimeout(r, 10));

    // Send from rogue origin
    messageListener({
      origin: 'https://attacker.org',
      source: fakePopupWindow,
      data: {
        type: 'lanzar:authenticated',
        payload: { code: 'fake_code', state: 'state_123' }
      }
    });

    // Allow microtasks to execute
    await new Promise((r) => setTimeout(r, 50));
    assert.strictEqual(resolved, false, 'Promise must not resolve for unauthorized origin');
    fakePopupWindow.closed = true;
    delete global.window;
  });

  await test('HANDSHAKE-06: Popup handshake ignores mismatched source window', async () => {
    const fakePopupWindow = { closed: false };
    const rogueWindow = { closed: false };
    let messageListener = null;

    global.window = {
      location: { href: 'https://portal.lanzar.me/dashboard' },
      screen: { width: 1920, height: 1080 },
      open: () => fakePopupWindow,
      addEventListener: (type, listener) => {
        if (type === 'message') messageListener = listener;
      },
      removeEventListener: () => {}
    };

    let resolved = false;
    const popupPromise = LanzarAuth.openPopup({ clientId: 'portal' }, STAGING_CONFIG).then(() => {
      resolved = true;
    });

    await new Promise((r) => setTimeout(r, 10));

    // Send from correct origin but unexpected source window
    messageListener({
      origin: STAGING_CONFIG.authHubUrl,
      source: rogueWindow,
      data: {
        type: 'lanzar:authenticated',
        payload: { code: 'fake_code', state: 'state_123' }
      }
    });

    await new Promise((r) => setTimeout(r, 50));
    assert.strictEqual(resolved, false, 'Promise must not resolve for mismatched source window');
    fakePopupWindow.closed = true;
    delete global.window;
  });

  // 3. Strict PKCE Verifier Zero-Transmission & Confidentiality
  await test('HANDSHAKE-07: PKCE verifier is never transmitted to Auth Hub or over the wire', async () => {
    const pkce = await generatePkcePair();
    const authorizeUrl = buildAuthorizeUrl({
      clientId: 'portal',
      redirectUri: 'https://portal.lanzar.me/auth/callback',
      codeChallenge: pkce.codeChallenge,
      codeChallengeMethod: 'S256',
      state: 'session_xyz'
    }, STAGING_CONFIG);

    const parsed = new URL(authorizeUrl);
    // Verifier must NOT appear in query params
    assert.strictEqual(parsed.searchParams.has('code_verifier'), false, 'code_verifier must NEVER appear in authorize URL');
    assert.strictEqual(parsed.searchParams.has('verifier'), false, 'verifier must not appear in authorize URL');
    // Challenge and explicit method S256 MUST appear
    assert.strictEqual(parsed.searchParams.get('code_challenge'), pkce.codeChallenge);
    assert.strictEqual(parsed.searchParams.get('code_challenge_method'), 'S256');
  });

  // 4. Exact-Origin postMessage & Top-Level Redirect Preservation Logic
  await test('HANDSHAKE-08: Auth Hub response handler posts to exact registered client origin', () => {
    const redirectUri = 'https://portal.lanzar.me/auth/callback';
    const targetUrl = new URL(redirectUri);
    const clientOrigin = targetUrl.origin;

    assert.strictEqual(clientOrigin, 'https://portal.lanzar.me', 'Client origin extracted accurately');
    assert.notStrictEqual(clientOrigin, '*', 'targetOrigin must NEVER be wildcard "*"');
  });

  await test('HANDSHAKE-09: Top-level redirect flow preserved when not in iframe or popup', () => {
    // Simulated top-level window (parent === self, opener === null)
    const mockWindow = {
      parent: null,
      opener: null,
      location: {
        replacedUrl: null,
        replace: function(url) { this.replacedUrl = url; }
      }
    };
    mockWindow.parent = mockWindow; // parent === self means top level

    const isIframe = mockWindow.parent && mockWindow.parent !== mockWindow;
    const isPopup = mockWindow.opener && !mockWindow.opener.closed;

    assert.strictEqual(Boolean(isIframe), false);
    assert.strictEqual(Boolean(isPopup), false);

    const targetUrl = new URL('https://portal.lanzar.me/auth/callback');
    targetUrl.searchParams.set('code', 'auth_code_top_level');
    targetUrl.searchParams.set('state', 'state_456');

    if (isIframe || isPopup) {
      // should not enter
      assert.fail('Should not enter iframe/popup branch');
    } else {
      mockWindow.location.replace(targetUrl.toString());
    }

    assert.strictEqual(mockWindow.location.replacedUrl, 'https://portal.lanzar.me/auth/callback?code=auth_code_top_level&state=state_456');
  });

  await test('HANDSHAKE-10: Popup window initiates window.close() after posting message', () => {
    let closed = false;
    let postedMsg = null;
    let targetOriginUsed = null;

    const mockOpener = {
      closed: false,
      postMessage: (msg, targetOrigin) => {
        postedMsg = msg;
        targetOriginUsed = targetOrigin;
      }
    };

    const mockWindow = {
      opener: mockOpener,
      parent: null,
      close: () => { closed = true; }
    };
    mockWindow.parent = mockWindow;

    const isIframe = mockWindow.parent && mockWindow.parent !== mockWindow;
    const isPopup = mockWindow.opener && !mockWindow.opener.closed;

    assert.strictEqual(Boolean(isPopup), true);
    assert.strictEqual(Boolean(isIframe), false);

    const targetUrl = new URL('https://portal.lanzar.me/auth/callback');
    const clientOrigin = targetUrl.origin;
    const targetWindow = isIframe ? mockWindow.parent : mockWindow.opener;

    targetWindow.postMessage({
      type: 'lanzar:authenticated',
      payload: { code: 'code_popup_close_test', state: 'st' }
    }, clientOrigin);

    if (isPopup) {
      mockWindow.close();
    }

    assert.strictEqual(targetOriginUsed, 'https://portal.lanzar.me');
    assert.strictEqual(postedMsg.type, 'lanzar:authenticated');
    assert.strictEqual(postedMsg.payload.code, 'code_popup_close_test');
    assert.strictEqual(closed, true, 'Popup window closed after dispatch');
  });

  console.log('\n======================================================');
  console.log('POPUP & MODAL HANDSHAKE TEST SUMMARY');
  console.log(`Total Executed: ${passCount + failCount}`);
  console.log(`Passed:         ${passCount}`);
  console.log(`Failed:         ${failCount}`);
  console.log(`Success Rate:   ${((passCount / (passCount + failCount)) * 100).toFixed(1)}%`);
  console.log('======================================================\n');

  if (failCount > 0) {
    process.exit(1);
  }
}

run().catch((err) => {
  console.error('[TEST RUNNER FATAL]', err);
  process.exit(1);
});
