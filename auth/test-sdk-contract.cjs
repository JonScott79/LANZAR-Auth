// test-sdk-contract.cjs
// Automated Contract & PKCE Verification Suite for LANZAR ID Client SDK
// Packaging and validation for <lanzar-auth-modal> v1.0.0

const assert = require('assert');
const crypto = require('crypto');

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

function recordTest(id, desc, passed, errDetail = null) {
  totalTests++;
  if (passed) {
    passedTests++;
    console.log(`  ✓ [PASS] ${id}: ${desc}`);
  } else {
    failedTests++;
    console.error(`  ✗ [FAIL] ${id}: ${desc}`);
    if (errDetail) console.error(`     Details: ${errDetail}`);
  }
}

async function runSdkContractTests() {
  console.log('\n======================================================');
  console.log('LANZAR ID — Client SDK Contract & PKCE Verification Suite');
  console.log('Component: <lanzar-auth-modal> & LanzarAuth SDK');
  console.log('Timestamp: ' + new Date().toISOString());
  console.log('======================================================\n');

  const {
    LanzarAuthModal,
    LanzarAuth,
    generateCodeVerifier,
    generateCodeChallenge,
    generatePkcePair,
    buildAuthorizeUrl,
    exchangeCodeForSession,
    sanitizeContinuationUrl,
    STAGING_CONFIG,
    PRODUCTION_CONFIG,
    DEVELOPMENT_CONFIG
  } = await import('./src/sdk/lanzar-auth-modal.js');

  // ----------------------------------------------------
  // Section 1: RFC 7636 PKCE Cryptographic Compliance
  // ----------------------------------------------------
  console.log('--- Section 1: RFC 7636 PKCE Compliance ---');

  // SDK-PKCE-1: Default verifier length and charset
  try {
    const verifier = generateCodeVerifier();
    const isLengthValid = verifier.length === 64;
    const isCharsetValid = /^[A-Za-z0-9\-._~]+$/.test(verifier);
    recordTest('SDK-PKCE-1', 'Verifier generates 64 characters from RFC 7636 unreserved charset', isLengthValid && isCharsetValid);
  } catch (e) {
    recordTest('SDK-PKCE-1', 'Verifier generates 64 characters from RFC 7636 unreserved charset', false, e.message);
  }

  // SDK-PKCE-2: Custom length boundaries (min 43, max 128)
  try {
    const vMin = generateCodeVerifier(43);
    const vMax = generateCodeVerifier(128);
    const boundsPassed = vMin.length === 43 && vMax.length === 128;
    recordTest('SDK-PKCE-2', 'Verifier enforces RFC 7636 valid length bounds (43 to 128 chars)', boundsPassed);
  } catch (e) {
    recordTest('SDK-PKCE-2', 'Verifier enforces RFC 7636 valid length bounds (43 to 128 chars)', false, e.message);
  }

  // SDK-PKCE-3: Out-of-bounds lengths rejected
  try {
    let rejectedUnder = false;
    let rejectedOver = false;
    try { generateCodeVerifier(42); } catch (e) { rejectedUnder = true; }
    try { generateCodeVerifier(129); } catch (e) { rejectedOver = true; }
    recordTest('SDK-PKCE-3', 'Verifier rejects lengths < 43 or > 128', rejectedUnder && rejectedOver);
  } catch (e) {
    recordTest('SDK-PKCE-3', 'Verifier rejects lengths < 43 or > 128', false, e.message);
  }

  // SDK-PKCE-4: Entropy / Uniqueness
  try {
    const set = new Set();
    for (let i = 0; i < 50; i++) {
      set.add(generateCodeVerifier(48));
    }
    recordTest('SDK-PKCE-4', '50 consecutively generated verifiers are strictly unique (high entropy)', set.size === 50);
  } catch (e) {
    recordTest('SDK-PKCE-4', '50 consecutively generated verifiers are strictly unique (high entropy)', false, e.message);
  }

  // SDK-PKCE-5: RFC 7636 Appendix B Test Vector Verification
  // Verifier: dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
  // Expected Challenge: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  try {
    const testVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    const expectedChallenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
    const computedChallenge = await generateCodeChallenge(testVerifier);
    recordTest('SDK-PKCE-5', 'SHA-256 Base64URL challenge matches RFC 7636 Appendix B reference vector', computedChallenge === expectedChallenge);
  } catch (e) {
    recordTest('SDK-PKCE-5', 'SHA-256 Base64URL challenge matches RFC 7636 Appendix B reference vector', false, e.message);
  }

  // SDK-PKCE-6: generatePkcePair helper bundle
  try {
    const pair = await generatePkcePair(50);
    const pass = Boolean(
      pair.codeVerifier &&
      pair.codeVerifier.length === 50 &&
      pair.codeChallenge &&
      pair.codeChallengeMethod === 'S256'
    );
    recordTest('SDK-PKCE-6', 'generatePkcePair generates complete pair with explicit S256 method', pass);
  } catch (e) {
    recordTest('SDK-PKCE-6', 'generatePkcePair generates complete pair with explicit S256 method', false, e.message);
  }

  // ----------------------------------------------------
  // Section 2: Authorize URL Construction & Strict Gating
  // ----------------------------------------------------
  console.log('\n--- Section 2: Authorize URL Construction ---');

  // SDK-URL-1: Standard Authorize URL Construction
  try {
    const authUrl = buildAuthorizeUrl({
      clientId: 'portal',
      redirectUri: 'https://portal.lanzar.me/auth/callback',
      codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      codeChallengeMethod: 'S256',
      state: 'st_random_12345'
    }, PRODUCTION_CONFIG);

    const parsed = new URL(authUrl);
    const pass = 
      parsed.origin === 'https://auth.lanzar.me' &&
      parsed.searchParams.get('client_id') === 'portal' &&
      parsed.searchParams.get('redirect_uri') === 'https://portal.lanzar.me/auth/callback' &&
      parsed.searchParams.get('code_challenge') === 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM' &&
      parsed.searchParams.get('code_challenge_method') === 'S256' &&
      parsed.searchParams.get('state') === 'st_random_12345';
    recordTest('SDK-URL-1', 'Authorize URL builds with all required OAuth/PKCE query parameters', pass);
  } catch (e) {
    recordTest('SDK-URL-1', 'Authorize URL builds with all required OAuth/PKCE query parameters', false, e.message);
  }

  // SDK-URL-2: Missing codeChallenge throws error
  try {
    let caught = false;
    try {
      buildAuthorizeUrl({
        clientId: 'portal',
        redirectUri: 'https://portal.lanzar.me/callback'
      }, PRODUCTION_CONFIG);
    } catch (e) {
      caught = e.message.includes('codeChallenge is required');
    }
    recordTest('SDK-URL-2', 'Missing codeChallenge fails closed during authorize URL construction', caught);
  } catch (e) {
    recordTest('SDK-URL-2', 'Missing codeChallenge fails closed during authorize URL construction', false, e.message);
  }

  // SDK-URL-3: Non-S256 method throws error
  try {
    let caught = false;
    try {
      buildAuthorizeUrl({
        clientId: 'portal',
        redirectUri: 'https://portal.lanzar.me/callback',
        codeChallenge: 'some_challenge',
        codeChallengeMethod: 'plain'
      }, PRODUCTION_CONFIG);
    } catch (e) {
      caught = e.message.includes('codeChallengeMethod must be S256');
    }
    recordTest('SDK-URL-3', 'Non-S256 codeChallengeMethod fails closed during authorize URL construction', caught);
  } catch (e) {
    recordTest('SDK-URL-3', 'Non-S256 codeChallengeMethod fails closed during authorize URL construction', false, e.message);
  }

  // SDK-URL-4: Account view URL construction
  try {
    const accountUrl = buildAuthorizeUrl({
      clientId: 'portal',
      redirectUri: 'https://portal.lanzar.me/',
      codeChallenge: 'some_challenge',
      view: 'account'
    }, PRODUCTION_CONFIG);

    const parsed = new URL(accountUrl);
    recordTest('SDK-URL-4', 'Account view sets /account path on Auth Hub URL', parsed.pathname === '/account');
  } catch (e) {
    recordTest('SDK-URL-4', 'Account view sets /account path on Auth Hub URL', false, e.message);
  }

  // ----------------------------------------------------
  // Section 3: Continuation URL Sanitization & Allowlist
  // ----------------------------------------------------
  console.log('\n--- Section 3: Continuation URL Sanitization ---');

  // SDK-SAN-1: Valid production service URLs allowed
  try {
    const portalUrl = 'https://portal.lanzar.me/dashboard';
    const ticketsUrl = 'https://tickets.lanzar.me/queue';
    const pythosUrl = 'https://pythos.lanzar.me/learn';
    const threadlineUrl = 'https://threadline.lanzar.me/feed';
    const aiUrl = 'https://ai.lanzar.me/models';

    const pPassed = sanitizeContinuationUrl(portalUrl, PRODUCTION_CONFIG) === portalUrl;
    const tPassed = sanitizeContinuationUrl(ticketsUrl, PRODUCTION_CONFIG) === ticketsUrl;
    const pyPassed = sanitizeContinuationUrl(pythosUrl, PRODUCTION_CONFIG) === pythosUrl;
    const thPassed = sanitizeContinuationUrl(threadlineUrl, PRODUCTION_CONFIG) === threadlineUrl;
    const aPassed = sanitizeContinuationUrl(aiUrl, PRODUCTION_CONFIG) === aiUrl;

    recordTest('SDK-SAN-1', 'All ecosystem services allowed under Production configuration', pPassed && tPassed && pyPassed && thPassed && aPassed);
  } catch (e) {
    recordTest('SDK-SAN-1', 'All ecosystem services allowed under Production configuration', false, e.message);
  }

  // SDK-SAN-2: Cross-environment URL fallbacks to default portal URL
  try {
    const prodTarget = 'https://portal.lanzar.me/dashboard';
    const result = sanitizeContinuationUrl(prodTarget, STAGING_CONFIG);
    recordTest('SDK-SAN-2', 'Cross-environment URL in Staging falls back to default staging portal', result === STAGING_CONFIG.defaultPortalUrl);
  } catch (e) {
    recordTest('SDK-SAN-2', 'Cross-environment URL in Staging falls back to default staging portal', false, e.message);
  }

  // SDK-SAN-3: Phishing / Malicious open redirect neutralized
  try {
    const malicious = 'https://attacker.com/steal-session?dest=lanzar.me';
    const result = sanitizeContinuationUrl(malicious, PRODUCTION_CONFIG);
    recordTest('SDK-SAN-3', 'Unlisted external phishing domain neutralized to default portal URL', result === PRODUCTION_CONFIG.defaultPortalUrl);
  } catch (e) {
    recordTest('SDK-SAN-3', 'Unlisted external phishing domain neutralized to default portal URL', false, e.message);
  }

  // SDK-SAN-4: Malformed or non-string inputs handled safely
  try {
    const r1 = sanitizeContinuationUrl(null, PRODUCTION_CONFIG);
    const r2 = sanitizeContinuationUrl(undefined, PRODUCTION_CONFIG);
    const r3 = sanitizeContinuationUrl('not a valid url ://', PRODUCTION_CONFIG);
    const allDefaulted = r1 === PRODUCTION_CONFIG.defaultPortalUrl &&
                         r2 === PRODUCTION_CONFIG.defaultPortalUrl &&
                         r3 === PRODUCTION_CONFIG.defaultPortalUrl;
    recordTest('SDK-SAN-4', 'Malformed inputs fail closed to default portal URL', allDefaulted);
  } catch (e) {
    recordTest('SDK-SAN-4', 'Malformed inputs fail closed to default portal URL', false, e.message);
  }

  // ----------------------------------------------------
  // Section 4: Token Exchange Contract Validation
  // ----------------------------------------------------
  console.log('\n--- Section 4: Token Exchange Contract ---');

  // SDK-EXC-1: Missing parameters fail closed before network call
  try {
    let caught = false;
    try {
      await exchangeCodeForSession({
        code: 'some_code',
        clientId: 'portal'
        // missing redirectUri and codeVerifier
      });
    } catch (e) {
      caught = e.message.includes('Missing required exchange parameters');
    }
    recordTest('SDK-EXC-1', 'exchangeCodeForSession validates required parameters before network fetch', caught);
  } catch (e) {
    recordTest('SDK-EXC-1', 'exchangeCodeForSession validates required parameters before network fetch', false, e.message);
  }

  // ----------------------------------------------------
  // Section 5: Web Component Lifecycle & Origin Isolation
  // ----------------------------------------------------
  console.log('\n--- Section 5: Web Component Handshake & Origin Verification ---');

  // SDK-WC-1: Component instantiation and config
  try {
    const modal = new LanzarAuthModal();
    const configMatches = modal._config.appEnv === 'staging';
    recordTest('SDK-WC-1', 'LanzarAuthModal instantiates with authoritative staging config', configMatches);
  } catch (e) {
    recordTest('SDK-WC-1', 'LanzarAuthModal instantiates with authoritative staging config', false, e.message);
  }

  // SDK-WC-2: Strict postMessage Origin Check
  try {
    const modal = new LanzarAuthModal();
    let eventDispatched = false;

    // Simulate attacker postMessage from wrong origin
    const attackerEvent = {
      origin: 'https://evil-attacker.com',
      data: {
        type: 'lanzar:authenticated',
        payload: { code: 'fake_code' }
      }
    };
    modal.dispatchEvent = () => { eventDispatched = true; };
    modal._onMessage(attackerEvent);

    recordTest('SDK-WC-2', 'postMessage from unapproved origin is rejected and discarded', !eventDispatched);
  } catch (e) {
    recordTest('SDK-WC-2', 'postMessage from unapproved origin is rejected and discarded', false, e.message);
  }

  // SDK-WC-3: Legitimate postMessage processes authentication event
  try {
    const modal = new LanzarAuthModal();
    const dispatchedEvents = [];

    modal._codeVerifier = 'legit_code_verifier_123456';
    modal.dispatchEvent = (customEvent) => {
      dispatchedEvents.push(customEvent);
    };

    const legitimateEvent = {
      origin: modal._config.authHubUrl,
      data: {
        type: 'lanzar:authenticated',
        payload: { code: 'legit_code_abc', state: 'st_123' }
      }
    };
    modal._onMessage(legitimateEvent);

    const authEvent = dispatchedEvents.find(e => e.type === 'lanzar:authenticated');
    const closeEvent = dispatchedEvents.find(e => e.type === 'lanzar:closed');

    const pass = 
      Boolean(authEvent) &&
      Boolean(closeEvent) &&
      authEvent.detail &&
      authEvent.detail.code === 'legit_code_abc' &&
      authEvent.detail.state === 'st_123' &&
      authEvent.detail.codeVerifier === 'legit_code_verifier_123456';
    recordTest('SDK-WC-3', 'Legitimate postMessage dispatches authenticated event with code and verifier and closes modal', pass);
  } catch (e) {
    recordTest('SDK-WC-3', 'Legitimate postMessage dispatches authenticated event with code and verifier and closes modal', false, e.message);
  }

  // ----------------------------------------------------
  // Summary
  // ----------------------------------------------------
  console.log('\n======================================================');
  console.log('SDK CONTRACT TEST SUMMARY');
  console.log(`Total Executed: ${totalTests}`);
  console.log(`Passed:         ${passedTests}`);
  console.log(`Failed:         ${failedTests}`);
  console.log(`Success Rate:   ${((passedTests / totalTests) * 100).toFixed(1)}%`);
  console.log('======================================================\n');

  if (failedTests > 0) {
    process.exit(1);
  }
}

runSdkContractTests().catch(err => {
  console.error('[FATAL SDK CONTRACT ERROR]', err);
  process.exit(1);
});
