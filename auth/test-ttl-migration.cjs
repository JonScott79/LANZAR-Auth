// test-ttl-migration.cjs
// Verification suite for dual-field ttlExpiresAt Firestore Native TTL migration

const assert = require('assert');
const {
  SESSION_TTL_GRACE_MS,
  CENTRAL_SESSION_TTL_GRACE_MS,
  TOKEN_FAMILY_TTL_GRACE_MS,
  PHONE_OTP_TTL_GRACE_MS,
  ADMIN_IDEMPOTENCY_TTL_GRACE_MS,
  parseExpiryToMs,
  computeTtlDate
} = require('./auth-backend/services/ttlHelper');
const { SessionService } = require('./auth-backend/sessionService');
const { CentralSessionService } = require('./auth-backend/services/centralSessionService');
const { SMSService } = require('./auth-backend/smsService');

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✓ [PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ [FAIL] ${name}: ${err.message}`);
    failed++;
  }
}

function createDocCaptureDb() {
  const writes = new Map();
  function docRef(path) {
    return {
      path,
      async get() {
        const d = writes.get(path);
        return { exists: d !== undefined, data: () => d };
      },
      async set(data) { writes.set(path, data); },
      async create(data) { writes.set(path, data); },
      async update(data) { writes.set(path, { ...(writes.get(path) || {}), ...data }); },
      collection(sub) { return colRef(`${path}/${sub}`); }
    };
  }
  function colRef(prefix) {
    return {
      doc(id) { return docRef(`${prefix}/${id || 'auto_' + writes.size}`); },
      async add(data) { writes.set(`${prefix}/auto_${writes.size}`, data); return { id: 'auto' }; },
      where() { return { get: async () => ({ empty: true, forEach: () => {} }) }; }
    };
  }
  return {
    writes,
    collection: (name) => colRef(name),
    async runTransaction(fn) {
      return fn({
        get: (ref) => ref.get(),
        set: (ref, data) => ref.set(data),
        update: (ref, data) => ref.update(data),
        delete: () => {}
      });
    }
  };
}

async function run() {
  console.log('\n================================================================');
  console.log('LANZAR ID — Dual-Field ttlExpiresAt Migration Verification');
  console.log('================================================================\n');

  await test('TTL-01: parseExpiryToMs & computeTtlDate accurately convert seconds, ms, ISO strings, and reject invalid inputs', async () => {
    const sec = 1800000000;
    const ms = sec * 1000;
    assert.strictEqual(parseExpiryToMs(sec, 'seconds'), ms);
    assert.strictEqual(parseExpiryToMs(ms, 'ms'), ms);
    assert.strictEqual(parseExpiryToMs(new Date(ms).toISOString()), ms);
    assert.strictEqual(parseExpiryToMs({ toMillis: () => ms }), ms);

    const ttlDate = computeTtlDate(sec, SESSION_TTL_GRACE_MS, 'seconds');
    assert(ttlDate instanceof Date);
    assert.strictEqual(ttlDate.getTime(), ms + SESSION_TTL_GRACE_MS);

    assert.throws(() => computeTtlDate('not-a-date', 0), /Invalid expiration/);
    assert.throws(() => computeTtlDate(null, 0), /Invalid expiration/);
  });

  await test('TTL-02: SessionService.createSession preserves ISO expiresAt and writes ttlExpiresAt = expiresAt + 24h', async () => {
    const db = createDocCaptureDb();
    const svc = new SessionService(db, {});
    const res = await svc.createSession({ uid: 'u1', clientId: 'portal', ipAddress: '127.0.0.1' });

    const doc = db.writes.get(`users/u1/sessions/${res.sessionId}`);
    assert.strictEqual(typeof doc.expiresAt, 'string');
    assert(doc.ttlExpiresAt instanceof Date);
    const diff = doc.ttlExpiresAt.getTime() - Date.parse(doc.expiresAt);
    assert.strictEqual(diff, SESSION_TTL_GRACE_MS);
  });

  await test('TTL-03: CentralSessionService writes ttlExpiresAt = absoluteExpiresAt (0 grace) on central_sessions and +24h on child sessions', async () => {
    const db = createDocCaptureDb();
    const cs = new CentralSessionService(db, { createCustomToken: async () => 'tok' }, { appEnv: 'staging' });
    const { centralSessionId, parentDoc } = await cs.createCentralSession({ uid: 'u2', ipAddress: '127.0.0.1' });

    const savedParent = db.writes.get(`users/u2/central_sessions/${centralSessionId}`);
    assert.strictEqual(typeof savedParent.absoluteExpiresAt, 'number');
    assert(savedParent.ttlExpiresAt instanceof Date);
    assert.strictEqual(savedParent.ttlExpiresAt.getTime(), parentDoc.absoluteExpiresAt * 1000 + CENTRAL_SESSION_TTL_GRACE_MS);

    // Seed user_security for exchangeChildSessionToken
    db.writes.set('user_security/u2', { tokenVersion: 1, accountStatus: 'active', role: 'customer' });
    const ex = await cs.exchangeChildSessionToken({ uid: 'u2', centralSessionId, clientAppId: 'portal' });
    const savedChild = db.writes.get(`users/u2/sessions/${ex.sessionId}`);
    assert.strictEqual(typeof savedChild.expiresAt, 'number');
    assert(savedChild.ttlExpiresAt instanceof Date);
    assert.strictEqual(savedChild.ttlExpiresAt.getTime(), savedChild.expiresAt * 1000 + SESSION_TTL_GRACE_MS);
  });

  await test('TTL-04: SMSService writes ISO expiresAt and ttlExpiresAt = expiresAt + 1h on phone_otps', async () => {
    const db = createDocCaptureDb();
    const sms = new SMSService(db, { sendOTP: async () => {} });
    await sms.sendVerificationOTP('u3', '+15551234567', '127.0.0.1');

    const doc = db.writes.get('phone_otps/+15551234567');
    assert.strictEqual(typeof doc.expiresAt, 'string');
    assert(doc.ttlExpiresAt instanceof Date);
    assert.strictEqual(doc.ttlExpiresAt.getTime() - Date.parse(doc.expiresAt), PHONE_OTP_TTL_GRACE_MS);
  });

  await test('TTL-05: Retention constants match approved policy table', async () => {
    assert.strictEqual(SESSION_TTL_GRACE_MS, 24 * 60 * 60 * 1000);
    assert.strictEqual(CENTRAL_SESSION_TTL_GRACE_MS, 0);
    assert.strictEqual(TOKEN_FAMILY_TTL_GRACE_MS, 7 * 24 * 60 * 60 * 1000);
    assert.strictEqual(PHONE_OTP_TTL_GRACE_MS, 60 * 60 * 1000);
    assert.strictEqual(ADMIN_IDEMPOTENCY_TTL_GRACE_MS, 0);
  });

  console.log('\n================================================================');
  console.log(`TTL MIGRATION VERIFICATION SUMMARY: ${passed} passed, ${failed} failed`);
  console.log('================================================================\n');
  if (failed > 0) process.exit(1);
}

run().catch((err) => {
  console.error('FATAL:', err);
  process.exit(1);
});
