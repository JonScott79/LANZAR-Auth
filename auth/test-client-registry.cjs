// test-client-registry.cjs
// Verification suite for LANZAR ID OAuth Client Registry Reconciliation (Phase E.1)

const assert = require('assert');
const { clients, getClient } = require('./auth-backend/clients');

console.log('\n======================================================');
console.log('LANZAR ID — OAuth Client Registry Verification Suite');
console.log('Target Specification: LID-ARCH-REV-015 / Phase E.1');
console.log(`Timestamp: ${new Date().toISOString()}`);
console.log('======================================================\n');

let passCount = 0;
let failCount = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ [PASS] ${name}`);
    passCount++;
  } catch (err) {
    console.error(`  ✗ [FAIL] ${name}: ${err.message}`);
    failCount++;
  }
}

// 1. Approved Clients Present
test('REG-01: Approved client "portal" is registered and enabled', () => {
  const client = getClient('portal');
  assert(client !== null, 'portal client must exist');
  assert(client.enabled === true, 'portal client must be enabled');
  assert(client.redirectUris.includes('https://portal.lanzar.me'), 'portal redirect URI must be present');
});

test('REG-02: Approved client "tickets" is registered and enabled', () => {
  const client = getClient('tickets');
  assert(client !== null, 'tickets client must exist');
  assert(client.enabled === true, 'tickets client must be enabled');
  assert(client.redirectUris.includes('https://tickets.lanzar.me'), 'tickets redirect URI must be present');
});

test('REG-03: Approved client "threadline" is registered and enabled', () => {
  const client = getClient('threadline');
  assert(client !== null, 'threadline client must exist');
  assert(client.enabled === true, 'threadline client must be enabled');
  assert(client.redirectUris.includes('https://threadline.lanzar.me'), 'threadline redirect URI must be present');
});

test('REG-04: Approved client "ai" is registered and enabled', () => {
  const client = getClient('ai');
  assert(client !== null, 'ai client must exist');
  assert(client.enabled === true, 'ai client must be enabled');
  assert(client.redirectUris.includes('https://ai.lanzar.me'), 'ai redirect URI must be present');
});

// 2. Unapproved / Legacy Clients Excised
test('REG-05: Legacy client "id" (id.lanzar.me) is completely removed from registry', () => {
  assert(clients['id'] === undefined, 'clients.id must be undefined');
  assert(getClient('id') === null, 'getClient("id") must return null');
});

test('REG-06: Unapproved client "pythos" (pythos.lanzar.me) is excluded from registry', () => {
  assert(clients['pythos'] === undefined, 'clients.pythos must be undefined');
  assert(getClient('pythos') === null, 'getClient("pythos") must return null');
});

test('REG-07: Unapproved client "mothership" (lanzar.me) is excluded from registry', () => {
  assert(clients['mothership'] === undefined, 'clients.mothership must be undefined');
  assert(getClient('mothership') === null, 'getClient("mothership") must return null');
});

test('REG-08: Registry strictly contains exactly 4 approved ecosystem clients', () => {
  const registeredKeys = Object.keys(clients).sort();
  const expectedKeys = ['ai', 'portal', 'threadline', 'tickets'].sort();
  assert.deepStrictEqual(registeredKeys, expectedKeys, `Expected registry keys to be strictly [${expectedKeys.join(', ')}], got [${registeredKeys.join(', ')}]`);
});

// 3. Unknown Client Resolution
test('REG-09: Arbitrary unknown clientId returns null', () => {
  assert.strictEqual(getClient('unknown_rogue_app'), null);
});

console.log('\n======================================================');
console.log('CLIENT REGISTRY TEST SUMMARY');
console.log(`Total Executed: ${passCount + failCount}`);
console.log(`Passed:         ${passCount}`);
console.log(`Failed:         ${failCount}`);
console.log(`Success Rate:   ${((passCount / (passCount + failCount)) * 100).toFixed(1)}%`);
console.log('======================================================\n');

if (failCount > 0) {
  process.exit(1);
}
