// test-key-retirement-and-telemetry.cjs
// Focused unit tests for automated signing-key retirement & admin telemetry signals.

const assert = require('assert');
const crypto = require('crypto');
const {
  SigningKeystore,
  MIN_SAFE_RETIREMENT_GRACE_SECONDS,
  DEFAULT_RETIREMENT_GRACE_SECONDS,
  validateRetirementGraceSeconds
} = require('./auth-backend/services/signingKeystore');
const { AuditLogService } = require('./auth-backend/services/auditLogService');

function createInMemoryDb() {
  const collections = new Map();
  function getCol(name) {
    if (!collections.has(name)) collections.set(name, new Map());
    return collections.get(name);
  }
  function makeDocRef(colName, id) {
    return {
      id,
      collection: (subCol) => makeColRef(`${colName}/${id}/${subCol}`),
      async get() {
        const data = getCol(colName).get(id);
        return { exists: data !== undefined, id, data: () => (data ? { ...data } : undefined) };
      },
      async set(data, opts) {
        const prev = opts && opts.merge ? (getCol(colName).get(id) || {}) : {};
        getCol(colName).set(id, { ...prev, ...data });
      },
      async update(patch) {
        const prev = getCol(colName).get(id);
        if (!prev) throw new Error(`Doc ${colName}/${id} not found`);
        getCol(colName).set(id, { ...prev, ...patch });
      }
    };
  }
  function makeColRef(name) {
    return {
      doc: (id) => makeDocRef(name, id),
      where: (field, op, val) => ({
        async get() {
          const docs = [];
          for (const [id, data] of getCol(name).entries()) {
            if (op === '==' && data[field] === val) {
              docs.push({ id, data: () => ({ ...data }) });
            }
          }
          return { empty: docs.length === 0, size: docs.length, docs };
        }
      }),
      async get() {
        const docs = [];
        for (const [id, data] of getCol(name).entries()) {
          docs.push({ id, data: () => ({ ...data }) });
        }
        return { empty: docs.length === 0, size: docs.length, docs };
      }
    };
  }
  return {
    _collections: collections,
    collection: (name) => makeColRef(name),
    async runTransaction(fn) {
      const tx = {
        get: (ref) => ref.get(),
        set: (ref, data, opts) => ref.set(data, opts),
        update: (ref, patch) => ref.update(patch)
      };
      return fn(tx);
    }
  };
}

async function run() {
  console.log('\n================================================================');
  console.log('LANZAR ID — Automated Key Retirement & Telemetry Unit Suite');
  console.log('================================================================\n');

  let passed = 0;

  // 1. Grace period floor enforcement
  assert.strictEqual(MIN_SAFE_RETIREMENT_GRACE_SECONDS, 3900);
  assert.strictEqual(DEFAULT_RETIREMENT_GRACE_SECONDS, 4200);
  assert.throws(() => validateRetirementGraceSeconds(60), /3900/);
  assert.throws(() => validateRetirementGraceSeconds('invalid'), /3900/);
  console.log('  ✓ [PASS] RET-01: Unsafe short grace periods (< 3900s) rejected');
  passed++;

  const db = createInMemoryDb();
  const auditLogService = new AuditLogService(db);
  const keystore = new SigningKeystore(db, { cacheTtlMs: 0 });

  const t0 = 1794850000000;
  const k1 = await keystore.ensureActiveSigningKey({ bypassCache: true });
  const tok1 = await keystore.signJwt({ sub: 'u1' }, { expiresInSeconds: 900, nowSec: Math.floor(t0 / 1000) });

  // 2. Rotate key -> k1 becomes verify_only with eligibleForRevocationAt
  const rot = await keystore.rotateSigningKey({ nowMs: t0 });
  const k2 = rot.newRecord;
  const k1Doc = (await db.collection('system_signing_keys').doc(k1.kid).get()).data();
  assert.strictEqual(k1Doc.status, 'verify_only');
  assert(k1Doc.eligibleForRevocationAt, 'eligibleForRevocationAt must be persisted');
  console.log('  ✓ [PASS] RET-02: rotateSigningKey() persists eligibleForRevocationAt on verify_only key');
  passed++;

  // 3. Before grace period expires -> k1 is NOT retired, tok1 still verifies
  const earlySweep = await keystore.retireEligibleKeys({ nowMs: t0 + 1800 * 1000, auditLogService });
  assert.strictEqual(earlySweep.retiredKids.length, 0);
  const verEarly = await keystore.verifyJwt(tok1, { bypassCache: true, nowSec: Math.floor(t0 / 1000) + 100 });
  assert.strictEqual(verEarly.valid, true);
  console.log('  ✓ [PASS] RET-03: verify_only key preserved in JWKS during grace period');
  passed++;

  // 4. After grace period expires -> k1 retired, k2 protected, audit log written, tok1 rejected
  const afterMs = t0 + (DEFAULT_RETIREMENT_GRACE_SECONDS + 1) * 1000;
  const lateSweep = await keystore.retireEligibleKeys({ nowMs: afterMs, auditLogService });
  assert.deepStrictEqual(lateSweep.retiredKids, [k1.kid]);
  const k1Retired = (await db.collection('system_signing_keys').doc(k1.kid).get()).data();
  const k2Active = (await db.collection('system_signing_keys').doc(k2.kid).get()).data();
  assert.strictEqual(k1Retired.status, 'revoked');
  assert.strictEqual(k1Retired.revocationReason, 'grace_period_elapsed');
  assert.strictEqual(k2Active.status, 'active');
  const auditDoc = (await db.collection('tenants').doc('lanzar').collection('admin_audit_logs').doc(`aud_key_retire_${k1.kid}`).get()).data();
  assert(auditDoc && auditDoc.operation === 'platform.signing_key.auto_retired', 'Audit log missing');
  const verAfter = await keystore.verifyJwt(tok1, { bypassCache: true, nowSec: Math.floor(t0 / 1000) + 100 });
  assert.strictEqual(verAfter.valid, false);
  assert.strictEqual(verAfter.reason, 'UNKNOWN_OR_REVOKED_KID');
  console.log('  ✓ [PASS] RET-04: Expired verify_only key retired, active key protected, audit logged, old token rejected');
  passed++;

  // 5. Idempotency: second sweep does not re-retire
  const repeatSweep = await keystore.retireEligibleKeys({ nowMs: afterMs + 60000, auditLogService });
  assert.strictEqual(repeatSweep.retiredKids.length, 0);
  console.log('  ✓ [PASS] RET-05: Repeated retirement sweep is idempotent');
  passed++;

  console.log(`\nALL ${passed} UNIT CHECKS PASSED.\n`);
}

run().catch((err) => {
  console.error('❌ TEST FAILED:', err);
  process.exit(1);
});
