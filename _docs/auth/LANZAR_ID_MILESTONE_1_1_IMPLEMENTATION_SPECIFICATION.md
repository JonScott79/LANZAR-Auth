# Milestone 1.1 Implementation Specification: Distributed Authorization Code Store

**Document ID:** LID-SPEC-M1.1-STORE-REV9-AUTHORITATIVE  
**Classification:** Confidential — Internal Master Engineering Specification  
**Status:** Authoritative & Implementation-Ready — Fully Verified via Live Firestore Emulator & In-Memory Suites  
**Component:** `auth-api.lanzar.me` / [`auth/auth-backend/store.js`](file:///C:/Users/jonny/.gemini/antigravity/worktrees/lanzar/lanzar_id_main_chat/auth/auth-backend/store.js)  
**Author:** Antigravity (Lead Systems Architect)  
**Date:** November 15, 2026  

---

## 1. Executive Summary & Problem Statement

The existing authorization code store in [`auth/auth-backend/store.js`](file:///C:/Users/jonny/.gemini/antigravity/worktrees/lanzar/lanzar_id_main_chat/auth/auth-backend/store.js) originally used an in-memory JavaScript `Map` (`this.codes = new Map()`) and split code lookup from redemption across separate asynchronous operations (`getCode` followed by `markUsed`).

This architecture created critical vulnerabilities:
1. **Container Restart Failure:** Railway container restarts destroy in-flight codes.
2. **Multi-Instance Incoherence:** Codes issued on one Railway container cannot be exchanged on another container.
3. **Concurrency Race Condition & Premature Activation:** Concurrent requests can both read `used === false`, compute PKCE, and mint duplicate sessions. Furthermore, if a replay arrives while token minting is underway, the ceremony lacks a durable state machine to abort the uncommitted session and leave usable refresh token state behind.
4. **Stale Worker Cleanup Collisions:** An older worker waking up after a pause or lease expiration must never revoke resources belonging to a newer worker or already committed sessions.

**Milestone 1.1 Objective:** Implement a distributed, transactional Cloud Firestore store (`/authorization_codes`) with:
- High-entropy CSPRNG codes (256-bit entropy) hashed with SHA-256 at rest.
- An explicit ceremony state machine (`ISSUED` → `REDEEMING` → `COMPLETED` | `COMPROMISED`).
- **Strict Read-Before-Write Transactional Sequencing:** In full compliance with Firestore transaction engine requirements, all document reads strictly precede all document mutations.
- **Strict Verification-First Idempotent Recovery:** Authorization code, client ID, exact redirect URI, and cryptographic PKCE verifier are validated **prior** to inspecting idempotency keys or returning cached receipts.
- **Mandatory Idempotency Keys:** Every redemption request must supply a valid, high-entropy `Idempotency-Key` (16–128 characters).
- **Stale-Worker Revocation Safety:** In `finalizeRedemption()`, stale workers verify ownership, ceremony ID, `pending_activation` status, and matching `redemptionLockId` and `fenceToken` before performing cleanup. Stale workers are fenced out and prohibited from mutating newer workers' resources.
- **Explicit Expired-Lock Takeover Policy:** In `initiateRedemption()`, an expired `REDEEMING` lock with a matching `Idempotency-Key` cleanly recovers the lease, cleans up old pending uncommitted records, advances `fenceToken`, and issues a new lease; a differing `Idempotency-Key` triggers compromise/replay defense (`COMPROMISED`, revoking old records).
- **Complete Cross-Document Relationship Validation:** `finalizeRedemption()` verifies that `session.familyId === issuedFamilyId` and `family.sessionId === issuedSessionId`, alongside matching UID, tenant ID, client ID, and ceremony ID across all three documents.
- **Failure-Handler Fencing Protection:** `handleRedemptionFailure()` enforces identical fencing checks so late network exceptions from older workers cannot revoke newer workers' active/pending resources.
- **Atomic Three-Document Session & Family Activation:** Sessions and token families are written in `pending_activation` state and atomically activated within `finalizeRedemption` only after verifying lock validity, existence, `pending_activation` status, and circular relationship pointers.
- **Immediate Durable Revocation via Token Families:** Session revocation and refresh-token family invalidation are executed synchronously within the compromise transaction via a bounded point-write to `/tenants/{tenantId}/token_families/{familyId}`.
- **Standard AES-256-GCM Token Receipt Encryption:** 12-byte (96-bit) IV and 16-byte (128-bit) authentication tag with Authenticated Additional Data (AAD) cryptographically binding ciphertext to `codeHash:clientId:tenantId:uid:ceremonyId`.
- **Reliable Security Outbox:** Staged events are processed via distributed lease locks, exponential backoff, and dead-letter queue (DLQ) escalation.
- **Strict Character-for-Character Redirect URI Matching:** Zero trailing-slash tolerance and zero wildcard matching.
- **Authoritative 60-Second Application Expiration:** Paired with 24-hour asynchronous forensic TTL retention.

---

## 2. Existing Call Sites & File Inventory

The store is consumed exclusively by `auth-backend` across exactly four call sites:

| Location | Existing Call Site | Milestone 1.1 Call Site | Functionality |
| :--- | :--- | :--- | :--- |
| [`server.js:62`](file:///C:/Projects/lanzar/auth/auth-backend/server.js#L62) | `const codeStore = new AuthorizationCodeStore();` | `const codeStore = new AuthorizationCodeStore(db);` | Inject Firestore database reference. |
| [`server.js:562`](file:///C:/Projects/lanzar/auth/auth-backend/server.js#L562) | `const code = await codeStore.createCode({...});` | `const code = await codeStore.createCode({...});` | Generates 256-bit CSPRNG code and writes document. |
| [`server.js:584`](file:///C:/Projects/lanzar/auth/auth-backend/server.js#L584) | `const record = await codeStore.getCode(code);` | Replaced by `codeStore.initiateRedemption({...})` | Atomically transitions from `ISSUED` to `REDEEMING`. |
| [`server.js:600`](file:///C:/Projects/lanzar/auth/auth-backend/server.js#L600) | `await codeStore.markUsed(code);` | Replaced by `codeStore.finalizeRedemption({...})` | Atomically activates session & family; sets `COMPLETED`. |

**Scope Boundary:** Zero files in `portal`, `tickets`, `pythos`, `threadline`, `ai`, or `homepage` import or consume `store.js`.

---

## 3. Database Schema & Document Contracts

### 3.1 Primary Collection: `/authorization_codes/{codeHash}`

Document key: `codeHash = crypto.createHash('sha256').update(code).digest('hex')`

```json
{
  "codeHash": "b5d4045c3f466fa91fe2cc6abe79232a1a57cdf104f7a26e716e0a1e2789df78",
  "ceremonyId": "crm_9a8f21bc0912",
  "status": "ISSUED", // "ISSUED" | "REDEEMING" | "COMPLETED" | "COMPROMISED" | "EXPIRED"
  "clientId": "portal",
  "tenantId": "lanzar",
  "uid": "Tcdyrq9vIVhfPeeDPnTrZIP553x1",
  "redirectUri": "https://portal.lanzar.me",
  "codeChallenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  "codeChallengeMethod": "S256",
  "authSessionId": "sess_initial_login_88f9",
  "scope": "openid profile email",
  "nonce": "n-0S6_WzA2Mj",
  "mfaVerified": true,
  "idempotencyKey": "idem_8f92b10a_4c21",
  "redemptionLockId": "lck_198f21a09b",
  "redemptionLockExpiresAt": "2026-11-15T04:14:15.000Z",
  "fenceToken": 1,
  "issuedSessionId": "sess_issued_9912a",
  "issuedFamilyId": "fam_88f921a09b",
  "issuedTokenReceipt": {
    "keyVersion": 1,
    "iv": "d3b0c44298fc1c149afbf4c8", // Exactly 12 bytes (96 bits) in hex
    "authTag": "9afbf4c8996fb924e2a1b0c98fa321bc", // Exactly 16 bytes (128 bits) in hex
    "ciphertext": "e2a1b0c98f..."
  },
  "replayAttemptCount": 0,
  "expiresAt": "2026-11-15T04:15:00.000Z", // 60 seconds from creation (Authoritative App TTL)
  "deleteAt": "2026-11-16T04:14:00.000Z",  // 24 hours from creation (Firestore TTL policy)
  "createdAt": "2026-11-15T04:14:00.000Z",
  "updatedAt": "2026-11-15T04:14:00.000Z"
}
```

### 3.2 Session Document: `/users/{uid}/sessions/{sessionId}`

```json
{
  "sessionId": "sess_issued_9912a",
  "uid": "Tcdyrq9vIVhfPeeDPnTrZIP553x1",
  "clientId": "portal",
  "tenantId": "lanzar",
  "ceremonyId": "crm_9a8f21bc0912",
  "familyId": "fam_88f921a09b",
  "status": "pending_activation", // "pending_activation" | "active" | "revoked"
  "revocationReason": null,
  "userAgent": "Mozilla/5.0 ...",
  "ipAddress": "198.51.100.42",
  "createdAt": "2026-11-15T04:14:05.000Z",
  "activatedAt": null,
  "revokedAt": null
}
```

### 3.3 Refresh Token Family Document: `/tenants/{tenantId}/token_families/{familyId}`

```json
{
  "familyId": "fam_88f921a09b",
  "ceremonyId": "crm_9a8f21bc0912",
  "uid": "Tcdyrq9vIVhfPeeDPnTrZIP553x1",
  "clientId": "portal",
  "tenantId": "lanzar",
  "sessionId": "sess_issued_9912a",
  "status": "pending_activation", // "pending_activation" | "active" | "revoked"
  "revocationReason": null,
  "currentActiveTokenHash": "7f83b1657ff1fc53...",
  "sequenceNumber": 1,
  "createdAt": "2026-11-15T04:14:05.000Z",
  "activatedAt": null,
  "revokedAt": null
}
```

### 3.4 Reliable Security Outbox: `/security_outbox/{eventId}`

```json
{
  "eventId": "sec_replay_b5d4045c3f_1_1763281900000",
  "tenantId": "lanzar",
  "uid": "Tcdyrq9vIVhfPeeDPnTrZIP553x1",
  "eventType": "AUTHORIZATION_CODE_REPLAY_ATTACK",
  "severity": "CRITICAL",
  "details": {
    "ceremonyId": "crm_9a8f21bc0912",
    "clientId": "portal",
    "codeHashPrefix": "b5d4045c...",
    "compromisedSessionId": "sess_issued_9912a",
    "compromisedFamilyId": "fam_88f921a09b",
    "authSessionId": "sess_initial_login_88f9"
  },
  "status": "pending", // "pending" | "leased" | "processed" | "dead_letter"
  "leaseOwner": null,
  "leaseExpiresAt": null,
  "retryCount": 0,
  "nextRetryAt": "2026-11-15T04:14:30.000Z",
  "createdAt": "2026-11-15T04:14:30.000Z",
  "processedAt": null
}
```

---

## 4. The Two-Phase Authorization Ceremony State Machine

```
[ Phase 1: initiateRedemption ]
        │
        ▼ (Firestore Transaction 1: Deterministic Reads-Before-Writes)
[ 1. READS: Read code document (and session + family docs if replay branch) ]
[ 2. VALIDATION: Code exists, client matches, redirect matches, PKCE S256 matches ]
        │
        ├── [ PKCE or Context Mismatch ] ──► REJECT IMMEDIATELY (Do NOT inspect idempotency key)
        │
        └── [ PKCE & Context Valid ]      ──► Inspect Ceremony Status:
                │
                ├── If `status === 'COMPLETED'`:
                │     ├── If matching `idempotencyKey` ──► Return `IDEMPOTENT_RECOVERY` (Decrypted Receipt)
                │     └── If mismatched/no key         ──► REPLAY DETECTED!
                │                                          • Writes: codeDoc.status = 'COMPROMISED'
                │                                          • Writes: sessionDoc.status = 'revoked'
                │                                          • Writes: familyDoc.status = 'revoked'
                │                                          • Writes: outboxDoc (staged incident)
                │                                          • Return REPLAY_DETECTED
                │
                ├── If `status === 'REDEEMING'`:
                │     ├── If lock active (!expired):
                │     │     ├── If matching `idempotencyKey` ──► Return `IN_PROGRESS` (Client safely waits)
                │     │     └── If conflicting key           ──► CONCURRENT COMPROMISE!
                │     │                                          • Writes: codeDoc.status = 'COMPROMISED'
                │     │                                          • Writes: Revoke pending session & family
                │     │                                          • Writes: Stage outbox conflict event
                │     │                                          • Return REPLAY_DETECTED
                │     │
                │     └── If lock expired:
                │           ├── If matching `idempotencyKey` ──► SAFE TAKEOVER & RECOVERY!
                │           │                                    • Writes: Revoke old stalled session & family
                │           │                                    • Writes: Advance fenceToken, new lockId, lease 15s
                │           │                                    • Writes: Stage takeover recovery event
                │           │                                    • Return SUCCESS to mint new session/family
                │           │
                │           └── If conflicting key           ──► CONCURRENT EXPIRED COMPROMISE!
                │                                                • Writes: codeDoc.status = 'COMPROMISED'
                │                                                • Writes: Revoke old pending records
                │                                                • Writes: Stage outbox conflict event
                │                                                • Return REPLAY_DETECTED
                │
                └── If `status === 'ISSUED'`:
                      • Writes: codeDoc.status = 'REDEEMING', lockId, fenceToken = 1, lease 15s
                      • Return `SUCCESS` to mint tokens
        │
        ▼
[ Token Minting & PENDING Session/Family Creation ]
• Worker generates `sessionId` and `familyId`.
• Cross-links pointers: `session.familyId = familyId`, `family.sessionId = sessionId`.
• Worker attaches fencing tokens: `redemptionLockId`, `fenceToken` to both pending docs.
• Writes `/users/{uid}/sessions/{sessionId}` with `status: "pending_activation"`.
• Writes `/tenants/{tenantId}/token_families/{familyId}` with `status: "pending_activation"`.
• Worker mints RS256 Access Token and ID Token.
• Encrypts token receipt using AES-256-GCM with AAD context binding.
        │
        ▼
[ Phase 2: finalizeRedemption ]
        │
        ▼ (Firestore Transaction 2: Atomic Three-Document Finalization)
[ 1. READS: Read `/authorization_codes/{codeHash}`, `/users/{uid}/sessions/{sessionId}`,
            and `/tenants/{tenantId}/token_families/{familyId}` ]
        │
        ├── If Stale Worker Fenced (`codeDoc.status !== 'REDEEMING'` OR `lockId !== myLockId` OR `fenceToken !== myFenceToken`):
        │     ──► STALE WORKER REVOCATION SAFETY CHECK:
        │         • Checks `canWorkerRevokeSession()` & `canWorkerRevokeFamily()`
        │         • MUST ONLY revoke if doc is `pending_activation` AND matches worker's `redemptionLockId` & `fenceToken`
        │         • NEVER revokes newer worker's active session or family!
        │         • Stage STALE_WORKER_FENCED outbox event; return { success: false, reason: 'STALE_WORKER_FENCED' }
        │
        ├── If Expired Lock OR Record Relationship Mismatch (`session.familyId !== issuedFamilyId` OR `family.sessionId !== issuedSessionId`):
        │     ──► FAIL CLOSED!
        │         • Revoke own pending records if safe.
        │         • Stage critical security outbox alert.
        │         • Return failure; fail closed.
        │
        └── If ALL invariants pass:
              • Writes: codeDoc.status = 'COMPLETED', store encrypted receipt.
              • Writes: sessionDoc.status = 'active', activatedAt = now.
              • Writes: familyDoc.status = 'active', activatedAt = now.
              • Deliver tokens to client.
```

---

## 5. Store Implementation & Cryptographic Algorithms

### 5.1 Dedicated Receipt Encryption Key Isolation, Rotation & AES-256-GCM

Receipt encryption enforces NIST SP 800-38D dimensions:
- **IV:** Exactly 12 bytes (96 bits) CSPRNG.
- **Auth Tag:** Exactly 16 bytes (128 bits).
- **AAD Context Binding:** Cryptographically binds ciphertext to `codeHash:clientId:tenantId:uid:ceremonyId`.
- **Fail-Closed Dedicated Key Isolation:** In production and staging, `RECEIPT_ENCRYPTION_KEY` must be a dedicated key providing at least 32 bytes (256 bits) of cryptographic entropy. Startup fails immediately (`validateReceiptKeyConfiguration`) if the key is missing, short, or uses development defaults. Silent fallback to `SESSION_SECRET` or hardcoded keys is strictly prohibited.
- **Multi-Version Key Rotation:** Key versions are resolved via `ACTIVE_RECEIPT_KEY_VERSION`, keyring mapping (`RECEIPT_ENCRYPTION_KEYS` JSON or `RECEIPT_ENCRYPTION_KEY_V{version}`), enabling decryption of tokens minted under earlier key versions during rotation windows.

```javascript
const GCM_IV_LENGTH = 12; // 96 bits (NIST SP 800-38D)
const GCM_TAG_LENGTH = 16; // 128 bits
const DEFAULT_RECEIPT_KEY_VERSION = 1;

function isProductionOrStaging() {
    const nodeEnv = process.env.NODE_ENV;
    const appEnv = process.env.APP_ENV;
    return nodeEnv === 'production' || appEnv === 'production' || appEnv === 'staging';
}

const KNOWN_DEV_RECEIPT_KEYS = [
    'LANZAR_ID_DEV_RECEIPT_SECRET_V1',
    'LANZAR_ID_DEV_RECEIPT_KEY_VERSION_1_TEST_ONLY_32B',
    'default_dev_secret',
    'dev_receipt_key',
    'lanzar_dev',
    'dev_secret'
];

function parseAndValidateReceiptKey(rawKey, version) {
    if (!rawKey) return null;
    let keyBuffer;
    if (Buffer.isBuffer(rawKey)) {
        keyBuffer = rawKey;
    } else if (typeof rawKey === 'string') {
        const trimmed = rawKey.trim();
        if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
            keyBuffer = Buffer.from(trimmed, 'hex');
        } else {
            keyBuffer = Buffer.from(trimmed, 'utf8');
        }
    } else {
        throw new Error(`Receipt encryption key for version ${version} has invalid type.`);
    }

    if (keyBuffer.length < 32) {
        throw new Error(`Receipt encryption key for version ${version} is invalid: must be at least 32 bytes (256 bits), got ${keyBuffer.length} bytes.`);
    }

    return keyBuffer.subarray(0, 32);
}

function parseActiveReceiptKeyVersion(rawValue) {
    if (rawValue === undefined || rawValue === null) {
        return DEFAULT_RECEIPT_KEY_VERSION;
    }
    const trimmed = String(rawValue).trim();
    if (trimmed === '') {
        return DEFAULT_RECEIPT_KEY_VERSION;
    }
    if (!/^[1-9]\d*$/.test(trimmed)) {
        throw new Error(`ACTIVE_RECEIPT_KEY_VERSION must be a positive integer, got "${rawValue}"`);
    }
    const parsed = Number(trimmed);
    if (!Number.isSafeInteger(parsed) || parsed < 1) {
        throw new Error(`ACTIVE_RECEIPT_KEY_VERSION must be a positive integer, got "${rawValue}"`);
    }
    return parsed;
}

function getActiveReceiptKeyVersion() {
    return parseActiveReceiptKeyVersion(process.env.ACTIVE_RECEIPT_KEY_VERSION);
}

/**
 * Resolves the raw receipt key entry from environment variables using the canonical
 * deterministic fallback order shared by startup validation and runtime resolution:
 * 1. RECEIPT_ENCRYPTION_KEYS[version] (JSON keyring)
 * 2. RECEIPT_ENCRYPTION_KEY_V{version}
 * 3. RECEIPT_ENCRYPTION_KEY (version 1 only)
 * 4. TOKEN_RECEIPT_KEY (version 1 development/non-production fallback only)
 */
function resolveRawReceiptKeyFromEnv(env, numericVersion) {
    if (env.RECEIPT_ENCRYPTION_KEYS) {
        let keyring;
        try {
            keyring = JSON.parse(env.RECEIPT_ENCRYPTION_KEYS);
        } catch (e) {
            throw new Error(`RECEIPT_ENCRYPTION_KEYS must be valid JSON: ${e.message}`);
        }
        if (keyring && typeof keyring === 'object') {
            const candidate = keyring[String(numericVersion)] || keyring[numericVersion];
            if (candidate) {
                return candidate;
            }
        }
    }

    const versionEnvVar = `RECEIPT_ENCRYPTION_KEY_V${numericVersion}`;
    if (env[versionEnvVar]) {
        return env[versionEnvVar];
    }

    if (numericVersion === 1) {
        if (env.RECEIPT_ENCRYPTION_KEY) {
            return env.RECEIPT_ENCRYPTION_KEY;
        }
        const isProdOrStagingEnv =
            env.NODE_ENV === 'production' ||
            env.APP_ENV === 'production' ||
            env.APP_ENV === 'staging';
        if (!isProdOrStagingEnv && env.TOKEN_RECEIPT_KEY) {
            return env.TOKEN_RECEIPT_KEY;
        }
    }

    return null;
}

function resolveReceiptKey(version = getActiveReceiptKeyVersion()) {
    const numericVersion = Number(version);
    if (!Number.isInteger(numericVersion) || numericVersion < 1) {
        throw new Error(`Unsupported receipt key version: ${version} (version must be a positive integer).`);
    }

    // 1. Check test keyring override
    if (receiptKeyringOverride) {
        if (receiptKeyringOverride[numericVersion]) {
            return parseAndValidateReceiptKey(receiptKeyringOverride[numericVersion], numericVersion);
        }
        throw new Error(`Unsupported receipt key version: ${numericVersion} (not found in active keyring).`);
    }

    // 2. Canonical deterministic environment lookup (JSON keyring -> V{n} -> V1 primary)
    const rawFromEnv = resolveRawReceiptKeyFromEnv(process.env, numericVersion);
    if (rawFromEnv) {
        return parseAndValidateReceiptKey(rawFromEnv, numericVersion);
    }

    // 3. In production or staging: FAIL CLOSED IMMEDIATELY. ZERO UNSAFE FALLBACKS!
    if (isProductionOrStaging()) {
        const envLabel = process.env.APP_ENV || process.env.NODE_ENV || 'production';
        throw new Error(`Dedicated receipt encryption key is missing for version ${numericVersion} in ${envLabel} environment. Dedicated key is required in production.`);
    }

    // 4. Explicitly isolated development/test fallback ONLY for version 1
    if (numericVersion === 1) {
        const devFallbackKey = `LANZAR_ID_DEV_RECEIPT_KEY_V1_TEST_ONLY_32B`;
        return crypto.createHash('sha256').update(devFallbackKey).digest();
    }

    throw new Error(`Unsupported receipt key version: ${numericVersion} (unconfigured key version).`);
}

function validateReceiptKeyConfiguration(env = process.env) {
    const nodeEnv = env.NODE_ENV;
    const appEnv = env.APP_ENV;
    const isProd = nodeEnv === 'production' || appEnv === 'production' || appEnv === 'staging';

    const activeVersion = parseActiveReceiptKeyVersion(env.ACTIVE_RECEIPT_KEY_VERSION);
    const keyRaw = resolveRawReceiptKeyFromEnv(env, activeVersion);

    if (isProd) {
        if (!keyRaw) {
            throw new Error(`RECEIPT_ENCRYPTION_KEY is required in ${appEnv || nodeEnv} environment for active key version ${activeVersion}.`);
        }
        if (typeof keyRaw === 'string') {
            const lower = keyRaw.toLowerCase();
            for (const devStr of KNOWN_DEV_RECEIPT_KEYS) {
                if (lower.includes(devStr.toLowerCase())) {
                    throw new Error(`RECEIPT_ENCRYPTION_KEY cannot use a development or default secret in ${appEnv || nodeEnv}.`);
                }
            }
        }
        parseAndValidateReceiptKey(keyRaw, activeVersion);
    } else if (keyRaw) {
        parseAndValidateReceiptKey(keyRaw, activeVersion);
    }
    return true;
}

function encryptTokenReceipt(payload, aadContext, options = {}) {
    if (!payload) throw new Error('Token payload is required for receipt encryption.');
    if (!aadContext || typeof aadContext !== 'string') {
        throw new Error('AAD context string is required for receipt encryption.');
    }

    const keyVersion = options.keyVersion || getActiveReceiptKeyVersion();
    const iv = crypto.randomBytes(GCM_IV_LENGTH);
    const key = resolveReceiptKey(keyVersion);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: GCM_TAG_LENGTH });
    cipher.setAAD(Buffer.from(aadContext, 'utf8'));

    const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
        keyVersion,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
        ciphertext: ciphertext.toString('base64')
    };
}

function decryptTokenReceipt(receipt, expectedAadContext) {
    if (!receipt || !receipt.iv || !receipt.authTag || !receipt.ciphertext) {
        throw new Error('Invalid receipt structure.');
    }
    const iv = Buffer.from(receipt.iv, 'hex');
    const authTag = Buffer.from(receipt.authTag, 'hex');
    const ciphertext = Buffer.from(receipt.ciphertext, 'base64');

    if (iv.length !== GCM_IV_LENGTH) throw new Error('Invalid IV dimension.');
    if (authTag.length !== GCM_TAG_LENGTH) throw new Error('Invalid Auth Tag dimension.');

    const version = receipt.keyVersion || DEFAULT_RECEIPT_KEY_VERSION;
    const key = resolveReceiptKey(version);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: GCM_TAG_LENGTH });
    decipher.setAAD(Buffer.from(expectedAadContext, 'utf8'));
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return JSON.parse(decrypted.toString('utf8'));
}
```

### 5.2 Verification-First Redemption (`initiateRedemption`)

```javascript
async initiateRedemption({ code, clientId, redirectUri, codeVerifier, idempotencyKey }) {
    // 1. Mandatory Idempotency-Key validation (16-128 chars)
    if (!idempotencyKey || typeof idempotencyKey !== 'string' || !/^[a-zA-Z0-9_-]{16,128}$/.test(idempotencyKey)) {
        return { status: 'INVALID_REQUEST', errorDescription: 'Missing or malformed Idempotency-Key (must be 16-128 characters).' };
    }

    if (!code || !clientId || !redirectUri || !codeVerifier) {
        return { status: 'INVALID_REQUEST', errorDescription: 'Missing required authorization parameters.' };
    }

    const codeHash = crypto.createHash('sha256').update(code).digest('hex');
    const codeRef = this.collection.doc(codeHash);

    return await this.db.runTransaction(async (transaction) => {
        const opTime = Date.now();
        // --- ALL READS MUST PRECEDE ALL WRITES ---
        const codeDoc = await transaction.get(codeRef);
        if (!codeDoc.exists) {
            return { status: 'NOT_FOUND', errorDescription: 'Authorization code not found.' };
        }

        const data = codeDoc.data();

        // 1. EXACT CLIENT ID MATCH
        if (data.clientId !== clientId) {
            return { status: 'CLIENT_MISMATCH', errorDescription: 'Client ID mismatch.' };
        }

        // 2. EXACT REDIRECT URI MATCH (Zero trailing-slash or wildcard tolerance)
        if (data.redirectUri !== redirectUri) {
            return { status: 'REDIRECT_MISMATCH', errorDescription: 'Redirect URI mismatch.' };
        }

        // 3. CRYPTOGRAPHIC PKCE S256 VERIFIER VALIDATION (MANDATORY BEFORE ANY RECOVERY INSPECTION)
        const calculatedChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
        if (calculatedChallenge !== data.codeChallenge) {
            return { status: 'PKCE_MISMATCH', errorDescription: 'PKCE challenge verification failed.' };
        }

        const lockExpiresMs = toEpochMs(data.redemptionLockExpiresAt);
        const lockExpired = !Number.isFinite(lockExpiresMs) || lockExpiresMs <= 0 || opTime > lockExpiresMs;

        // 4. PRE-READ DOCUMENTS FOR CLEANUP (REPLAY/CONFLICT/EXPIRED-LOCK BRANCHES) BEFORE ANY WRITES
        // Preserves Firestore read-before-write requirement across:
        // - Completed code replay (different key)
        // - Redeeming active concurrent conflict (different key)
        // - Redeeming expired-lock takeover (same key - cleans up old pending records)
        // - Redeeming expired-lock conflict (different key - revokes and marks compromised)
        let sessionDoc = null;
        let familyDoc = null;
        let sessionRef = null;
        let familyRef = null;

        const needsCleanupPreRead =
            (data.status === 'COMPLETED' && data.idempotencyKey !== idempotencyKey) ||
            (data.status === 'REDEEMING' && (!lockExpired && data.idempotencyKey !== idempotencyKey)) ||
            (data.status === 'REDEEMING' && lockExpired);

        if (needsCleanupPreRead && data.issuedSessionId && data.issuedFamilyId) {
            const tenantId = data.tenantId || 'lanzar';
            sessionRef = this.db.collection('users').doc(data.uid).collection('sessions').doc(data.issuedSessionId);
            familyRef = this.db.collection('tenants').doc(tenantId).collection('token_families').doc(data.issuedFamilyId);
            sessionDoc = await transaction.get(sessionRef);
            familyDoc = await transaction.get(familyRef);
        }

        // --- ALL WRITES COMMENCE BELOW THIS LINE (ZERO READS ALLOWED PAST THIS POINT) ---

        // --- BRANCH A: CEREMONY ALREADY COMPLETED ---
        if (data.status === 'COMPLETED') {
            if (data.idempotencyKey === idempotencyKey) {
                // Legitimate recovery: Decrypt cached token receipt with AAD check
                const aadContext = `${codeHash}:${data.clientId}:${data.tenantId}:${data.uid}:${data.ceremonyId}`;
                const decryptedReceipt = decryptTokenReceipt(data.issuedTokenReceipt, aadContext);
                return {
                    status: 'IDEMPOTENT_RECOVERY',
                    tokenReceipt: decryptedReceipt,
                    record: data
                };
            }

            // Differing Idempotency Key: Replay Attack Detected
            const attemptSeq = (data.replayAttemptCount || 0) + 1;
            const eventId = `sec_replay_${codeHash.slice(0, 16)}_${attemptSeq}_${opTime}`;

            transaction.update(codeRef, {
                status: 'COMPROMISED',
                replayAttemptCount: attemptSeq,
                lastReplayAt: new Date(opTime)
            });

            const sessionMissing = !data.issuedSessionId || !sessionDoc || !sessionDoc.exists;
            const familyMissing = !data.issuedFamilyId || !familyDoc || !familyDoc.exists;
            const codeFenceValid = Number.isInteger(data.fenceToken) && data.fenceToken > 0;
            const sessionIndependentlyVerified = Boolean(
                sessionRef && (codeFenceValid ? canReplayRevokeSession(sessionDoc, codeDoc) : canContainByCeremonyAndLock(sessionDoc, codeDoc))
            );
            const familyIndependentlyVerified = Boolean(
                familyRef && (codeFenceValid ? canReplayRevokeFamily(familyDoc, codeDoc) : canContainByCeremonyAndLock(familyDoc, codeDoc))
            );
            const pairEligible = Boolean(
                codeFenceValid &&
                sessionIndependentlyVerified &&
                familyIndependentlyVerified &&
                canReplayRevokePair(sessionDoc, familyDoc, codeDoc)
            );

            if (sessionIndependentlyVerified) {
                transaction.update(sessionRef, {
                    status: 'revoked',
                    revocationReason: 'authorization_code_replay_compromise',
                    revokedAt: new Date(opTime)
                });
            }
            if (familyIndependentlyVerified) {
                transaction.update(familyRef, {
                    status: 'revoked',
                    revocationReason: 'authorization_code_replay_compromise',
                    revokedAt: new Date(opTime)
                });
            }

            if (!pairEligible && typeof data.ceremonyId === 'string' && data.ceremonyId) {
                transaction.set(this.db.collection('compromised_ceremonies').doc(data.ceremonyId), {
                    ceremonyId: data.ceremonyId,
                    codeHash,
                    uid: data.uid,
                    tenantId: data.tenantId,
                    clientId: data.clientId,
                    reason: !codeFenceValid ? 'invalid_code_fence_token_replay_compromise' : 'authorization_code_replay_compromise',
                    compromisedAt: new Date(opTime)
                });
            }

            if (!pairEligible) {
                const integrityEventType = (sessionMissing || familyMissing)
                    ? 'CRITICAL_SECURITY_RECORD_MISSING'
                    : 'CRITICAL_REPLAY_PAIR_INTEGRITY_FAILURE';
                const integrityPrefix = (sessionMissing || familyMissing) ? 'sec_integrity' : 'sec_pair_integrity';
                const integrityEventId = `${integrityPrefix}_${codeHash.slice(0, 16)}_${attemptSeq}_${opTime}`;

                transaction.set(this.db.collection('security_outbox').doc(integrityEventId), {
                    eventId: integrityEventId,
                    tenantId: data.tenantId,
                    uid: data.uid,
                    eventType: integrityEventType,
                    severity: 'CRITICAL',
                    details: {
                        ceremonyId: data.ceremonyId,
                        expectedSessionId: data.issuedSessionId,
                        expectedFamilyId: data.issuedFamilyId,
                        codeFenceToken: data.fenceToken ?? null,
                        sessionMissing,
                        familyMissing,
                        sessionInconsistent: !sessionMissing && !sessionIndependentlyVerified,
                        familyInconsistent: !familyMissing && !familyIndependentlyVerified,
                        pairInconsistent: !sessionMissing && !familyMissing && sessionIndependentlyVerified && familyIndependentlyVerified && !pairEligible,
                        sessionIndependentlyVerified,
                        familyIndependentlyVerified,
                        sessionRevoked: sessionIndependentlyVerified,
                        familyRevoked: familyIndependentlyVerified
                    },
                    status: 'pending',
                    retryCount: 0,
                    nextRetryAt: new Date(opTime),
                    createdAt: new Date(opTime)
                });
            }

            transaction.set(this.db.collection('security_outbox').doc(eventId), {
                eventId,
                tenantId: data.tenantId,
                uid: data.uid,
                eventType: 'AUTHORIZATION_CODE_REPLAY_DETECTED',
                severity: 'CRITICAL',
                details: {
                    attemptedIdempotencyKey: idempotencyKey,
                    originalIdempotencyKey: data.idempotencyKey,
                    ceremonyId: data.ceremonyId,
                    clientId: data.clientId,
                    codeHashPrefix: codeHash.slice(0, 16) + '...'
                },
                status: 'pending',
                retryCount: 0,
                nextRetryAt: new Date(opTime),
                createdAt: new Date(opTime)
            });

            return {
                status: 'REPLAY_DETECTED',
                errorDescription: 'Authorization code has already been redeemed.'
            };
        }

        // --- BRANCH B: CEREMONY ALREADY COMPROMISED ---
        if (data.status === 'COMPROMISED') {
            return {
                status: 'REPLAY_DETECTED',
                errorDescription: 'Authorization code ceremony was previously compromised.'
            };
        }

        // --- BRANCH C: CEREMONY CURRENTLY IN REDEEMING STATE ---
        if (data.status === 'REDEEMING') {
            const isLeaseValid = Number.isFinite(lockExpiresMs) && lockExpiresMs > 0;
            if (!isLeaseValid) {
                // Fail closed immediately on missing, zero, negative, malformed, or non-finite lease expiration
                const attemptSeq = (data.replayAttemptCount || 0) + 1;
                const eventId = `sec_invalid_lease_${codeHash.slice(0, 16)}_${attemptSeq}_${opTime}`;

                transaction.update(codeRef, {
                    status: 'COMPROMISED',
                    failureReason: 'invalid_lock_expiration',
                    replayAttemptCount: attemptSeq,
                    lastReplayAt: new Date(opTime)
                });

                const workerOpts = {
                    targetSessionId: data.issuedSessionId,
                    targetFamilyId: data.issuedFamilyId
                };
                if (sessionRef && canWorkerRevokeSession(sessionDoc, codeDoc, data.redemptionLockId, data.fenceToken, workerOpts)) {
                    transaction.update(sessionRef, {
                        status: 'revoked',
                        revocationReason: 'invalid_lock_expiration',
                        revokedAt: new Date(opTime)
                    });
                }
                if (familyRef && canWorkerRevokeFamily(familyDoc, codeDoc, data.redemptionLockId, data.fenceToken, workerOpts)) {
                    transaction.update(familyRef, {
                        status: 'revoked',
                        revocationReason: 'invalid_lock_expiration',
                        revokedAt: new Date(opTime)
                    });
                }

                transaction.set(this.db.collection('security_outbox').doc(eventId), {
                    eventId,
                    tenantId: data.tenantId,
                    uid: data.uid,
                    eventType: 'CORRUPT_LEASE_METADATA_DEFENSE',
                    severity: 'CRITICAL',
                    details: {
                        ceremonyId: data.ceremonyId,
                        clientId: data.clientId,
                        codeHashPrefix: codeHash.slice(0, 16) + '...',
                        rawLeaseValue: String(data.redemptionLockExpiresAt),
                        parsedLeaseMs: lockExpiresMs
                    },
                    status: 'pending',
                    retryCount: 0,
                    nextRetryAt: new Date(opTime),
                    createdAt: new Date(opTime)
                });

                return { status: 'REPLAY_DETECTED', errorDescription: 'Invalid redemption lock expiration metadata.' };
            }

            if (!lockExpired) {
                if (data.idempotencyKey === idempotencyKey) {
                    return {
                        status: 'IN_PROGRESS',
                        errorDescription: 'Redemption in progress for this idempotency key. Please wait and retry.'
                    };
                }

                // Concurrent conflict: differing idempotency key while lock active
                const attemptSeq = (data.replayAttemptCount || 0) + 1;
                const eventId = `sec_conflict_${codeHash.slice(0, 16)}_${attemptSeq}_${opTime}`;

                transaction.update(codeRef, {
                    status: 'COMPROMISED',
                    replayAttemptCount: attemptSeq,
                    lastReplayAt: new Date(opTime)
                });

                const conflictWorkerOpts = {
                    targetSessionId: data.issuedSessionId,
                    targetFamilyId: data.issuedFamilyId
                };
                if (sessionRef && canWorkerRevokeSession(sessionDoc, codeDoc, data.redemptionLockId, data.fenceToken, conflictWorkerOpts)) {
                    transaction.update(sessionRef, {
                        status: 'revoked',
                        revocationReason: 'concurrent_redemption_conflict',
                        revokedAt: new Date(opTime)
                    });
                }
                if (familyRef && canWorkerRevokeFamily(familyDoc, codeDoc, data.redemptionLockId, data.fenceToken, conflictWorkerOpts)) {
                    transaction.update(familyRef, {
                        status: 'revoked',
                        revocationReason: 'concurrent_redemption_conflict',
                        revokedAt: new Date(opTime)
                    });
                }

                transaction.set(this.db.collection('security_outbox').doc(eventId), {
                    eventId,
                    tenantId: data.tenantId,
                    uid: data.uid,
                    eventType: 'CONCURRENT_REDEMPTION_CONFLICT',
                    severity: 'CRITICAL',
                    details: {
                        attemptedIdempotencyKey: idempotencyKey,
                        originalIdempotencyKey: data.idempotencyKey,
                        ceremonyId: data.ceremonyId,
                        clientId: data.clientId,
                        codeHashPrefix: codeHash.slice(0, 16) + '...'
                    },
                    status: 'pending',
                    retryCount: 0,
                    nextRetryAt: new Date(opTime),
                    createdAt: new Date(opTime)
                });

                return { status: 'REPLAY_DETECTED', errorDescription: 'Concurrent redemption conflict.' };
            } else {
                // Lock has EXPIRED! Explicit policy:
                // 1. Different idempotency key -> Conflict/Replay Defense!
                if (data.idempotencyKey !== idempotencyKey) {
                    const attemptSeq = (data.replayAttemptCount || 0) + 1;
                    const eventId = `sec_expired_conflict_${codeHash.slice(0, 16)}_${attemptSeq}_${opTime}`;

                    transaction.update(codeRef, {
                        status: 'COMPROMISED',
                        replayAttemptCount: attemptSeq,
                        lastReplayAt: new Date(opTime)
                    });

                    const oldWorkerLockId = data.redemptionLockId;
                    const oldWorkerFence = data.fenceToken;
                    const workerOpts = {
                        targetSessionId: data.issuedSessionId,
                        targetFamilyId: data.issuedFamilyId
                    };

                    if (sessionRef && sessionDoc && sessionDoc.exists &&
                        canWorkerRevokeSession(sessionDoc, codeDoc, oldWorkerLockId, oldWorkerFence, workerOpts)) {
                        transaction.update(sessionRef, {
                            status: 'revoked',
                            revocationReason: 'expired_lock_conflict_compromise',
                            revokedAt: new Date(opTime)
                        });
                    }
                    if (familyRef && familyDoc && familyDoc.exists &&
                        canWorkerRevokeFamily(familyDoc, codeDoc, oldWorkerLockId, oldWorkerFence, workerOpts)) {
                        transaction.update(familyRef, {
                            status: 'revoked',
                            revocationReason: 'expired_lock_conflict_compromise',
                            revokedAt: new Date(opTime)
                        });
                    }

                    transaction.set(this.db.collection('security_outbox').doc(eventId), {
                        eventId,
                        tenantId: data.tenantId,
                        uid: data.uid,
                        eventType: 'CONCURRENT_REDEMPTION_CONFLICT',
                        severity: 'CRITICAL',
                        details: {
                            reason: 'expired_lock_different_idempotency_key',
                            ceremonyId: data.ceremonyId,
                            clientId: data.clientId,
                            codeHashPrefix: codeHash.slice(0, 16) + '...'
                        },
                        status: 'pending',
                        retryCount: 0,
                        nextRetryAt: new Date(opTime),
                        createdAt: new Date(opTime)
                    });

                    return { status: 'REPLAY_DETECTED', errorDescription: 'Concurrent redemption conflict on expired lock.' };
                }

                // 2. Same idempotency key -> Safe Takeover / Recovery!
                const oldWorkerLockId = data.redemptionLockId;
                const oldWorkerFence = data.fenceToken;
                const workerOpts = {
                    targetSessionId: data.issuedSessionId,
                    targetFamilyId: data.issuedFamilyId
                };

                if (sessionRef && sessionDoc && sessionDoc.exists &&
                    canWorkerRevokeSession(sessionDoc, codeDoc, oldWorkerLockId, oldWorkerFence, workerOpts)) {
                    transaction.update(sessionRef, {
                        status: 'revoked',
                        revocationReason: 'expired_lease_takeover_cleanup',
                        revokedAt: new Date(opTime)
                    });
                }
                if (familyRef && familyDoc && familyDoc.exists &&
                    canWorkerRevokeFamily(familyDoc, codeDoc, oldWorkerLockId, oldWorkerFence, workerOpts)) {
                    transaction.update(familyRef, {
                        status: 'revoked',
                        revocationReason: 'expired_lease_takeover_cleanup',
                        revokedAt: new Date(opTime)
                    });
                }

                const nextFence = (data.fenceToken || 0) + 1;
                const newLockId = crypto.randomBytes(16).toString('hex');
                const takeoverSeq = (data.takeoverCount || 0) + 1;

                transaction.update(codeRef, {
                    status: 'REDEEMING',
                    redemptionLockId: newLockId,
                    redemptionLockExpiresAt: new Date(opTime + 15000), // 15s lease
                    fenceToken: nextFence,
                    takeoverCount: takeoverSeq,
                    lastTakeoverAt: new Date(opTime),
                    issuedSessionId: null,
                    issuedFamilyId: null,
                    redeemedAt: new Date(opTime)
                });

                const takeoverEventId = `sec_takeover_${codeHash.slice(0, 16)}_${takeoverSeq}_${opTime}`;
                transaction.set(this.db.collection('security_outbox').doc(takeoverEventId), {
                    eventId: takeoverEventId,
                    tenantId: data.tenantId,
                    uid: data.uid,
                    eventType: 'REDEMPTION_LOCK_TAKEOVER_RECOVERY',
                    severity: 'WARN',
                    details: {
                        codeHashPrefix: codeHash.slice(0, 16),
                        takeoverSeq,
                        priorLockId: oldWorkerLockId,
                        newLockId,
                        fenceToken: nextFence
                    },
                    status: 'pending',
                    retryCount: 0,
                    nextRetryAt: new Date(opTime),
                    createdAt: new Date(opTime)
                });

                return {
                    status: 'SUCCESS',
                    codeHash,
                    redemptionLockId: newLockId,
                    fenceToken: nextFence,
                    record: {
                        ...data,
                        status: 'REDEEMING',
                        redemptionLockId: newLockId,
                        fenceToken: nextFence
                    }
                };
            }
        }

        // --- BRANCH D: NORMAL ISSUED STATE CLAIM & STRICT EXPIRATION CHECK ---
        if (data.status === 'EXPIRED') {
            return {
                status: 'EXPIRED',
                errorDescription: 'Authorization code has expired.'
            };
        }
        if (data.status !== 'ISSUED') {
            return {
                status: 'INVALID_REQUEST',
                errorDescription: `Invalid code status: ${data.status}`
            };
        }

        const expiresAtMs = toEpochMs(data.expiresAt);
        if (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
            transaction.update(codeRef, {
                status: 'EXPIRED',
                failureReason: 'invalid_code_expiration',
                expiredAt: new Date(opTime)
            });
            return {
                status: 'EXPIRED',
                errorDescription: 'Authorization code has invalid or missing expiration.'
            };
        }
        if (opTime > expiresAtMs) {
            transaction.update(codeRef, {
                status: 'EXPIRED',
                failureReason: 'code_expired',
                expiredAt: new Date(opTime)
            });
            return {
                status: 'EXPIRED',
                errorDescription: 'Authorization code has expired.'
            };
        }

        const redemptionLockId = crypto.randomBytes(16).toString('hex');
        const redemptionLockExpiresAt = new Date(opTime + 15000); // 15s lease
        const fenceToken = 1;

        transaction.update(codeRef, {
            status: 'REDEEMING',
            idempotencyKey,
            redemptionLockId,
            redemptionLockExpiresAt,
            fenceToken,
            redeemedAt: new Date(opTime)
        });

        return {
            status: 'SUCCESS',
            codeHash,
            redemptionLockId,
            fenceToken,
            record: {
                ...data,
                status: 'REDEEMING',
                idempotencyKey,
                redemptionLockId,
                fenceToken
            }
        };
    });
}
```

### 5.3 Conditional & Atomic Staged Record Pointer Registration (`registerStagedRecords`)

To prevent stale workers from overwriting authorization code pointers after a lease expiration and takeover, pointer registration is executed within a dedicated Firestore transaction verifying current ownership and fencing tokens before mutating `issuedSessionId` or `issuedFamilyId`.

```javascript
async registerStagedRecords({
    codeHash,
    redemptionLockId,
    fenceToken,
    uid,
    tenantId,
    clientId,
    ceremonyId,
    issuedSessionId,
    issuedFamilyId
}) {
    if (!codeHash || !redemptionLockId || !fenceToken || !issuedSessionId || !issuedFamilyId) {
        return { success: false, reason: 'INVALID_PARAMETERS' };
    }

    const codeRef = this.collection.doc(codeHash);
    const sessionRef = this.db.collection('users').doc(uid).collection('sessions').doc(issuedSessionId);
    const familyRef = this.db.collection('tenants').doc(tenantId || 'lanzar').collection('token_families').doc(issuedFamilyId);

    return await this.db.runTransaction(async (transaction) => {
        const opTime = Date.now();
        // --- 1. ALL TRANSACTION READS PRECEDING ALL WRITES ---
        const [codeDoc, sessionDoc, familyDoc] = await Promise.all([
            transaction.get(codeRef),
            transaction.get(sessionRef),
            transaction.get(familyRef)
        ]);

        if (!codeDoc.exists) return { success: false, reason: 'CODE_NOT_FOUND' };
        if (!sessionDoc.exists) return { success: false, reason: 'STAGED_SESSION_NOT_FOUND' };
        if (!familyDoc.exists) return { success: false, reason: 'STAGED_FAMILY_NOT_FOUND' };

        const codeData = codeDoc.data();
        const sessionData = sessionDoc.data();
        const familyData = familyDoc.data();

        // 2. Status must be REDEEMING
        if (codeData.status !== 'REDEEMING') {
            return { success: false, reason: `INVALID_CODE_STATUS_${codeData.status}` };
        }

        // 3. Lease lock validation (FAIL-CLOSED: must be positive, finite, and unexpired)
        const lockExpiresMs = toEpochMs(codeData.redemptionLockExpiresAt);
        if (!Number.isFinite(lockExpiresMs) || lockExpiresMs <= 0) {
            transaction.update(codeRef, {
                status: 'COMPROMISED',
                failureReason: 'invalid_lock_expiration',
                lastReplayAt: new Date(opTime)
            });
            if (sessionDoc.exists && sessionData.redemptionLockId === redemptionLockId && sessionData.fenceToken === fenceToken && sessionData.status === 'pending_activation') {
                transaction.update(sessionRef, { status: 'revoked', revocationReason: 'invalid_lock_expiration', revokedAt: new Date(opTime) });
            }
            if (familyDoc.exists && familyData.redemptionLockId === redemptionLockId && familyData.fenceToken === fenceToken && familyData.status === 'pending_activation') {
                transaction.update(familyRef, { status: 'revoked', revocationReason: 'invalid_lock_expiration', revokedAt: new Date(opTime) });
            }
            return { success: false, reason: 'INVALID_LOCK_EXPIRATION' };
        }
        if (opTime > lockExpiresMs) {
            transaction.update(codeRef, {
                status: 'COMPROMISED',
                failureReason: 'lock_expired',
                lastReplayAt: new Date(opTime)
            });
            if (sessionDoc.exists && sessionData.redemptionLockId === redemptionLockId && sessionData.fenceToken === fenceToken && sessionData.status === 'pending_activation') {
                transaction.update(sessionRef, { status: 'revoked', revocationReason: 'lock_expired', revokedAt: new Date(opTime) });
            }
            if (familyDoc.exists && familyData.redemptionLockId === redemptionLockId && familyData.fenceToken === fenceToken && familyData.status === 'pending_activation') {
                transaction.update(familyRef, { status: 'revoked', revocationReason: 'lock_expired', revokedAt: new Date(opTime) });
            }
            return { success: false, reason: 'LOCK_EXPIRED' };
        }

        // 4. Fencing validation: Lock ID and Fence Token must strictly match THIS worker
        if (codeData.redemptionLockId !== redemptionLockId || codeData.fenceToken !== fenceToken) {
            return { success: false, reason: 'STALE_WORKER_FENCED' };
        }

        // 5. Code metadata ownership validation
        const expectedTenant = tenantId || 'lanzar';
        if (codeData.ceremonyId !== ceremonyId ||
            codeData.uid !== uid ||
            (codeData.tenantId || 'lanzar') !== expectedTenant ||
            codeData.clientId !== clientId) {
            return { success: false, reason: 'METADATA_MISMATCH' };
        }

        // 6. Staged records status: Both must be 'pending_activation'
        if (sessionData.status !== 'pending_activation' || familyData.status !== 'pending_activation') {
            return { success: false, reason: 'STAGED_RECORD_NOT_PENDING' };
        }

        // 7. Staged records fencing tokens: Both must carry current worker's lock ID and fenceToken
        if (sessionData.redemptionLockId !== redemptionLockId || sessionData.fenceToken !== fenceToken ||
            familyData.redemptionLockId !== redemptionLockId || familyData.fenceToken !== fenceToken) {
            return { success: false, reason: 'STAGED_RECORD_FENCING_MISMATCH' };
        }

        // 8. Staged records ownership validation (UID, tenantId, clientId, ceremonyId)
        if (sessionData.uid !== uid || familyData.uid !== uid ||
            sessionData.clientId !== clientId || familyData.clientId !== clientId ||
            sessionData.ceremonyId !== ceremonyId || familyData.ceremonyId !== ceremonyId ||
            sessionData.tenantId !== expectedTenant || familyData.tenantId !== expectedTenant) {
            return { success: false, reason: 'STAGED_RECORD_OWNERSHIP_MISMATCH' };
        }

        // 9. Document identity & circular pointer integrity
        if (sessionData.sessionId !== issuedSessionId || familyData.familyId !== issuedFamilyId ||
            sessionData.familyId !== issuedFamilyId || familyData.sessionId !== issuedSessionId) {
            return { success: false, reason: 'STAGED_RECORD_POINTER_MISMATCH' };
        }

        // 10. Pointer conflict protection on code record
        if (codeData.issuedSessionId && codeData.issuedSessionId !== issuedSessionId) {
            return { success: false, reason: 'SESSION_POINTER_CONFLICT' };
        }
        if (codeData.issuedFamilyId && codeData.issuedFamilyId !== issuedFamilyId) {
            return { success: false, reason: 'FAMILY_POINTER_CONFLICT' };
        }

        // --- ALL WRITES COMMENCE ---
        transaction.update(codeRef, {
            issuedSessionId,
            issuedFamilyId,
            stagedAt: new Date(opTime)
        });

        return { success: true };
    });
}
```

### 5.4 Strengthened Stale Worker Revocation Safety Predicates

```javascript
/**
 * Strengthened Stale-Worker Safety Predicate: Verifies if a worker is authorized to revoke a session document.
 * Validates all applicable ownership relationships, including UID, tenant, client, ceremony,
 * document identity, session/family cross-references, and fencing generation.
 */
function canWorkerRevokeSession(sessionDoc, codeDoc, redemptionLockId, fenceToken, options = {}) {
    if (!sessionDoc || !sessionDoc.exists) return false;
    const sessionData = sessionDoc.data();
    // Must be in pending_activation status (NEVER revoke active session!)
    if (sessionData.status !== 'pending_activation') return false;
    // Fencing protection: Must strictly match THIS worker's lock ID and fence token
    if (sessionData.redemptionLockId !== redemptionLockId || sessionData.fenceToken !== fenceToken) {
        return false;
    }
    // Ceremony match if codeDoc exists
    if (codeDoc && codeDoc.exists) {
        const codeData = codeDoc.data();
        if (sessionData.ceremonyId !== codeData.ceremonyId) return false;
        if (sessionData.tenantId !== codeData.tenantId) return false;
        if (sessionData.uid !== codeData.uid) return false;
        if (sessionData.clientId !== codeData.clientId) return false;
    }
    // Document identity validation
    if (options.targetSessionId && sessionData.sessionId !== options.targetSessionId) {
        return false;
    }
    // Cross-reference validation to companion family
    if (options.targetFamilyId && sessionData.familyId !== options.targetFamilyId) {
        return false;
    }
    return true;
}

/**
 * Strengthened Stale-Worker Safety Predicate: Verifies if a worker is authorized to revoke a token family.
 * Validates all applicable ownership relationships, including UID, tenant, client, ceremony,
 * document identity, session/family cross-references, and fencing generation.
 */
function canWorkerRevokeFamily(familyDoc, codeDoc, redemptionLockId, fenceToken, options = {}) {
    if (!familyDoc || !familyDoc.exists) return false;
    const familyData = familyDoc.data();
    // Must be in pending_activation status (NEVER revoke active family!)
    if (familyData.status !== 'pending_activation') return false;
    // Fencing protection: Must strictly match THIS worker's lock ID and fence token
    if (familyData.redemptionLockId !== redemptionLockId || familyData.fenceToken !== fenceToken) {
        return false;
    }
    // Ceremony match if codeDoc exists
    if (codeDoc && codeDoc.exists) {
        const codeData = codeDoc.data();
        if (familyData.ceremonyId !== codeData.ceremonyId) return false;
        if (familyData.tenantId !== codeData.tenantId) return false;
        if (familyData.uid !== codeData.uid) return false;
        if (familyData.clientId !== codeData.clientId) return false;
    }
    // Document identity validation
    if (options.targetFamilyId && familyData.familyId !== options.targetFamilyId) {
        return false;
    }
    // Cross-reference validation to companion session
    if (options.targetSessionId && familyData.sessionId !== options.targetSessionId) {
        return false;
    }
    return true;
}
```

### 5.5 Atomic Finalization & Comprehensive Invariant Enforcement (`finalizeRedemption`)

```javascript
async finalizeRedemption({
    codeHash,
    redemptionLockId,
    fenceToken,
    uid,
    tenantId,
    issuedSessionId,
    issuedFamilyId,
    rawTokensPayload
}) {
    const codeRef = this.collection.doc(codeHash);
    const sessionRef = this.db.collection('users').doc(uid).collection('sessions').doc(issuedSessionId);
    const familyRef = this.db.collection('tenants').doc(tenantId).collection('token_families').doc(issuedFamilyId);

    const workerOptions = {
        targetSessionId: issuedSessionId,
        targetFamilyId: issuedFamilyId
    };

    return await this.db.runTransaction(async (transaction) => {
        const opTime = Date.now();
        // --- ALL READS MUST PRECEDE ALL WRITES ---
        const [codeDoc, sessionDoc, familyDoc] = await Promise.all([
            transaction.get(codeRef),
            transaction.get(sessionRef),
            transaction.get(familyRef)
        ]);

        // Missing record handling: fail closed, clean up companions, stage security incident
        if (!codeDoc.exists || !sessionDoc.exists || !familyDoc.exists) {
            if (canWorkerRevokeSession(sessionDoc, codeDoc, redemptionLockId, fenceToken, workerOptions)) {
                transaction.update(sessionRef, { status: 'revoked', revocationReason: 'missing_security_record', revokedAt: new Date(opTime) });
            }
            if (canWorkerRevokeFamily(familyDoc, codeDoc, redemptionLockId, fenceToken, workerOptions)) {
                transaction.update(familyRef, { status: 'revoked', revocationReason: 'missing_security_record', revokedAt: new Date(opTime) });
            }
            if (codeDoc.exists) {
                transaction.update(codeRef, { status: 'COMPROMISED', lastReplayAt: new Date(opTime) });
            }

            const missingEventId = `sec_missing_${codeHash.slice(0, 16)}_${opTime}`;
            const missingRef = this.db.collection('security_outbox').doc(missingEventId);
            transaction.set(missingRef, {
                eventId: missingEventId,
                tenantId: tenantId || 'unknown',
                uid: uid || 'unknown',
                eventType: 'CRITICAL_SECURITY_RECORD_MISSING',
                severity: 'CRITICAL',
                details: {
                    codeMissing: !codeDoc.exists,
                    sessionMissing: !sessionDoc.exists,
                    familyMissing: !familyDoc.exists,
                    issuedSessionId,
                    issuedFamilyId
                },
                status: 'pending',
                retryCount: 0,
                nextRetryAt: new Date(opTime),
                createdAt: new Date(opTime)
            });

            if (!codeDoc.exists) return { success: false, reason: 'CODE_NOT_FOUND' };
            if (!sessionDoc.exists) return { success: false, reason: 'SESSION_NOT_FOUND' };
            return { success: false, reason: 'FAMILY_NOT_FOUND' };
        }

        const codeData = codeDoc.data();
        const sessionData = sessionDoc.data();
        const familyData = familyDoc.data();

        // 1. REPLAY DETECTION DURING MINTING
        if (codeData.status === 'COMPROMISED') {
            if (canWorkerRevokeSession(sessionDoc, codeDoc, redemptionLockId, fenceToken, workerOptions)) {
                transaction.update(sessionRef, { status: 'revoked', revocationReason: 'compromised_during_minting', revokedAt: new Date(opTime) });
            }
            if (canWorkerRevokeFamily(familyDoc, codeDoc, redemptionLockId, fenceToken, workerOptions)) {
                transaction.update(familyRef, { status: 'revoked', revocationReason: 'compromised_during_minting', revokedAt: new Date(opTime) });
            }
            return { success: false, reason: 'COMPROMISED_DURING_ISSUANCE' };
        }

        // 2. STALE WORKER FENCING SAFETY (Requirement 1 & 2)
        // A stale worker MUST NEVER revoke resources belonging to a newer worker or active resources.
        if (codeData.status !== 'REDEEMING' || codeData.redemptionLockId !== redemptionLockId || codeData.fenceToken !== fenceToken) {
            // Only clean up if this session strictly belongs to THIS stale worker's attempt and is still pending
            if (canWorkerRevokeSession(sessionDoc, codeDoc, redemptionLockId, fenceToken, workerOptions)) {
                transaction.update(sessionRef, { status: 'revoked', revocationReason: 'stale_worker_fenced', revokedAt: new Date(opTime) });
            }
            if (canWorkerRevokeFamily(familyDoc, codeDoc, redemptionLockId, fenceToken, workerOptions)) {
                transaction.update(familyRef, { status: 'revoked', revocationReason: 'stale_worker_fenced', revokedAt: new Date(opTime) });
            }

            const fenceEventId = `sec_fence_${codeHash.slice(0, 16)}_${opTime}`;
            transaction.set(this.db.collection('security_outbox').doc(fenceEventId), {
                eventId: fenceEventId,
                tenantId,
                uid,
                eventType: 'STALE_WORKER_FENCED',
                severity: 'HIGH',
                details: { codeHashPrefix: codeHash.slice(0, 16), expectedLock: redemptionLockId, actualLock: codeData.redemptionLockId },
                status: 'pending',
                retryCount: 0,
                nextRetryAt: new Date(opTime),
                createdAt: new Date(opTime)
            });
            return { success: false, reason: 'STALE_WORKER_FENCED' };
        }

        // 3. EXPIRED LOCK CLEANUP (Strict fail-closed: must be positive, finite, and unexpired)
        const lockExpiresMs = toEpochMs(codeData.redemptionLockExpiresAt);
        if (!Number.isFinite(lockExpiresMs) || lockExpiresMs <= 0 || opTime > lockExpiresMs) {
            transaction.update(codeRef, {
                status: 'COMPROMISED',
                failureReason: !Number.isFinite(lockExpiresMs) || lockExpiresMs <= 0 ? 'invalid_lock_expiration' : 'lock_expired',
                lastReplayAt: new Date(opTime)
            });
            if (canWorkerRevokeSession(sessionDoc, codeDoc, redemptionLockId, fenceToken, workerOptions)) {
                transaction.update(sessionRef, { status: 'revoked', revocationReason: 'redemption_lock_expired', revokedAt: new Date(opTime) });
            }
            if (canWorkerRevokeFamily(familyDoc, codeDoc, redemptionLockId, fenceToken, workerOptions)) {
                transaction.update(familyRef, { status: 'revoked', revocationReason: 'redemption_lock_expired', revokedAt: new Date(opTime) });
            }

            const lockEventId = `sec_lock_exp_${codeHash.slice(0, 16)}_${opTime}`;
            transaction.set(this.db.collection('security_outbox').doc(lockEventId), {
                eventId: lockEventId,
                tenantId,
                uid,
                eventType: 'REDEMPTION_LOCK_EXPIRED',
                severity: 'HIGH',
                details: { codeHashPrefix: codeHash.slice(0, 16), issuedSessionId, issuedFamilyId },
                status: 'pending',
                retryCount: 0,
                nextRetryAt: new Date(opTime),
                createdAt: new Date(opTime)
            });
            return { success: false, reason: !Number.isFinite(lockExpiresMs) || lockExpiresMs <= 0 ? 'INVALID_LOCK_EXPIRATION' : 'LOCK_EXPIRED' };
        }

        // 4. INVALID RECORD STATUS CLEANUP
        if (sessionData.status !== 'pending_activation' || familyData.status !== 'pending_activation') {
            transaction.update(codeRef, { status: 'COMPROMISED', failureReason: 'invalid_status_during_finalization', lastReplayAt: new Date(opTime) });
            if (canWorkerRevokeSession(sessionDoc, codeDoc, redemptionLockId, fenceToken, workerOptions)) {
                transaction.update(sessionRef, { status: 'revoked', revocationReason: 'invalid_session_or_family_status', revokedAt: new Date(opTime) });
            }
            if (canWorkerRevokeFamily(familyDoc, codeDoc, redemptionLockId, fenceToken, workerOptions)) {
                transaction.update(familyRef, { status: 'revoked', revocationReason: 'invalid_session_or_family_status', revokedAt: new Date(opTime) });
            }

            const statusEventId = `sec_invalid_status_${codeHash.slice(0, 16)}_${opTime}`;
            transaction.set(this.db.collection('security_outbox').doc(statusEventId), {
                eventId: statusEventId,
                tenantId,
                uid,
                eventType: 'INVALID_RECORD_STATUS_DURING_FINALIZATION',
                severity: 'CRITICAL',
                details: { sessionStatus: sessionData.status, familyStatus: familyData.status },
                status: 'pending',
                retryCount: 0,
                nextRetryAt: new Date(opTime),
                createdAt: new Date(opTime)
            });
            return {
                success: false,
                reason: sessionData.status !== 'pending_activation' ? 'INVALID_SESSION_STATUS' : 'INVALID_FAMILY_STATUS'
            };
        }

        // 5. COMPLETE RELATIONSHIP & TENANT VALIDATION
        // Enforces circular pointers, cross-document relational integrity, session tenant, and code registration pointers
        const relationshipsValid =
            sessionData.uid === codeData.uid &&
            familyData.uid === codeData.uid &&
            sessionData.clientId === codeData.clientId &&
            familyData.clientId === codeData.clientId &&
            sessionData.ceremonyId === codeData.ceremonyId &&
            familyData.ceremonyId === codeData.ceremonyId &&
            sessionData.tenantId === codeData.tenantId &&
            familyData.tenantId === codeData.tenantId &&
            sessionData.sessionId === issuedSessionId &&
            familyData.familyId === issuedFamilyId &&
            sessionData.familyId === issuedFamilyId &&
            familyData.sessionId === issuedSessionId &&
            sessionData.redemptionLockId === redemptionLockId &&
            sessionData.fenceToken === fenceToken &&
            familyData.redemptionLockId === redemptionLockId &&
            familyData.fenceToken === fenceToken &&
            codeData.issuedSessionId === issuedSessionId &&
            codeData.issuedFamilyId === issuedFamilyId;

        if (!relationshipsValid) {
            transaction.update(codeRef, {
                status: 'COMPROMISED',
                failureReason: 'relationship_mismatch',
                lastReplayAt: new Date(opTime)
            });
            if (canWorkerRevokeSession(sessionDoc, codeDoc, redemptionLockId, fenceToken, workerOptions)) {
                transaction.update(sessionRef, { status: 'revoked', revocationReason: 'record_relationship_mismatch', revokedAt: new Date(opTime) });
            }
            if (canWorkerRevokeFamily(familyDoc, codeDoc, redemptionLockId, fenceToken, workerOptions)) {
                transaction.update(familyRef, { status: 'revoked', revocationReason: 'record_relationship_mismatch', revokedAt: new Date(opTime) });
            }

            const relEventId = `sec_rel_mismatch_${codeHash.slice(0, 16)}_${opTime}`;
            transaction.set(this.db.collection('security_outbox').doc(relEventId), {
                eventId: relEventId,
                tenantId,
                uid,
                eventType: 'RECORD_RELATIONSHIP_MISMATCH',
                severity: 'CRITICAL',
                details: {
                    issuedSessionId,
                    issuedFamilyId,
                    sessionDocFamilyId: sessionData.familyId,
                    familyDocSessionId: familyData.sessionId,
                    sessionTenant: sessionData.tenantId,
                    familyTenant: familyData.tenantId,
                    codeTenant: codeData.tenantId
                },
                status: 'pending',
                retryCount: 0,
                nextRetryAt: new Date(opTime),
                createdAt: new Date(opTime)
            });
            return { success: false, reason: 'RECORD_RELATIONSHIP_MISMATCH' };
        }

        // 6. ENCRYPT RECOVERY RECEIPT WITH AAD CONTEXT BINDING
        const aadContext = `${codeHash}:${codeData.clientId}:${codeData.tenantId}:${codeData.uid}:${codeData.ceremonyId}`;
        const encryptedReceipt = encryptTokenReceipt(rawTokensPayload, aadContext);

        // 7. COMMIT ATOMIC TRIPLE-WRITE ACTIVATION
        transaction.update(codeRef, {
            status: 'COMPLETED',
            issuedSessionId,
            issuedFamilyId,
            issuedTokenReceipt: encryptedReceipt,
            completedAt: new Date(opTime)
        });

        transaction.update(sessionRef, {
            status: 'active',
            activatedAt: new Date(opTime)
        });

        transaction.update(familyRef, {
            status: 'active',
            activatedAt: new Date(opTime)
        });

        return { success: true };
    });
}
```

### 5.6 Failure Cleanup Handler with Fencing Protections (`handleRedemptionFailure`)

```javascript
async handleRedemptionFailure({
    codeHash,
    redemptionLockId,
    fenceToken,
    uid,
    tenantId,
    sessionId,
    familyId,
    errorReason
}) {
    const codeRef = this.collection.doc(codeHash);
    const sessionRef = sessionId ? this.db.collection('users').doc(uid).collection('sessions').doc(sessionId) : null;
    const familyRef = familyId ? this.db.collection('tenants').doc(tenantId).collection('token_families').doc(familyId) : null;

    const workerOptions = {
        targetSessionId: sessionId,
        targetFamilyId: familyId
    };

    return await this.db.runTransaction(async (transaction) => {
        const opTime = Date.now();
        // --- 1. ALL READS PRECEDE ALL WRITES ---
        const codeDoc = await transaction.get(codeRef);
        const sessionDoc = sessionRef ? await transaction.get(sessionRef) : null;
        const familyDoc = familyRef ? await transaction.get(familyRef) : null;

        const isCurrentCodeWorker = codeDoc.exists &&
            codeDoc.data().status === 'REDEEMING' &&
            codeDoc.data().redemptionLockId === redemptionLockId &&
            codeDoc.data().fenceToken === fenceToken;

        const canRevokeSession = canWorkerRevokeSession(sessionDoc, codeDoc, redemptionLockId, fenceToken, workerOptions);
        const canRevokeFamily = canWorkerRevokeFamily(familyDoc, codeDoc, redemptionLockId, fenceToken, workerOptions);

        if (!isCurrentCodeWorker && !canRevokeSession && !canRevokeFamily) {
            const staleEventId = `sec_stale_fail_${codeHash.slice(0, 16)}_${opTime}`;
            transaction.set(this.db.collection('security_outbox').doc(staleEventId), {
                eventId: staleEventId,
                tenantId: tenantId || 'unknown',
                uid: uid || 'unknown',
                eventType: 'STALE_WORKER_FAILURE_FENCED',
                severity: 'WARN',
                details: {
                    codeHashPrefix: codeHash.slice(0, 16),
                    staleLockId: redemptionLockId,
                    staleFenceToken: fenceToken,
                    attemptedSessionId: sessionId,
                    attemptedFamilyId: familyId
                },
                status: 'pending',
                retryCount: 0,
                nextRetryAt: new Date(opTime),
                createdAt: new Date(opTime)
            });
            return { success: false, reason: 'STALE_WORKER_FENCED' };
        }

        // --- 2. WRITES COMMENCE ---
        if (canRevokeSession) {
            transaction.update(sessionRef, {
                status: 'revoked',
                revocationReason: errorReason || 'redemption_minting_failure',
                revokedAt: new Date(opTime)
            });
        }

        if (canRevokeFamily) {
            transaction.update(familyRef, {
                status: 'revoked',
                revocationReason: errorReason || 'redemption_minting_failure',
                revokedAt: new Date(opTime)
            });
        }

        if (isCurrentCodeWorker) {
            transaction.update(codeRef, {
                status: 'COMPROMISED',
                failureReason: errorReason || 'minting_or_encryption_failure',
                lastReplayAt: new Date(opTime)
            });
        }

        const failureEventId = `sec_fail_${codeHash.slice(0, 16)}_${opTime}`;
        transaction.set(this.db.collection('security_outbox').doc(failureEventId), {
            eventId: failureEventId,
            tenantId: tenantId || 'unknown',
            uid: uid || 'unknown',
            eventType: 'REDEMPTION_PROCESSING_FAILURE',
            severity: 'HIGH',
            details: {
                codeHashPrefix: codeHash.slice(0, 16),
                errorReason,
                sessionId,
                familyId
            },
            status: 'pending',
            retryCount: 0,
            nextRetryAt: new Date(opTime),
            createdAt: new Date(opTime)
        });

        return { success: true };
    });
}
```

## 6. Three-Tier Token Revocation Latency & Security Architecture

| Revocation Tier | Target Document | Latency / Propagation Time | Security Guarantee | Appropriate Consumer |
| :--- | :--- | :--- | :--- | :--- |
| **Tier 1: Online Session Validation** | `/users/{uid}/sessions/{sessionId}` | **Synchronous at Transaction Commit** (Actual execution latency 5–30ms) | Sub-millisecond to 15ms database check. If session document has `status === 'revoked'`, API immediately rejects request with HTTP 401. | **Mandatory** for LANZAR sensitive operations: password resets, MFA changes, billing changes, admin actions. |
| **Tier 2: Refresh Token Family Invalidation** | `/tenants/{tenantId}/token_families/{familyId}` | **Synchronous at Transaction Commit** (Actual execution latency 5–30ms) | Evaluated during every token refresh grant. If family document has `status === 'revoked'`, the grant is blocked immediately. | All refresh grant calls (`grant_type=refresh_token`). |
| **Tier 3: Offline Asymmetric JWT Validation** | Stateless RS256 Access Token verification | **Bounded by Access Token Lifespan (Strictly 15 Minutes)** | High-throughput offline validation using cached JWKS. Does not call database. **Does NOT provide immediate revocation.** | Low-risk, high-throughput read operations (e.g. search, static asset views). |

---

## 7. Reliable Security Outbox Worker & Dead-Letter Handling

```
[ Outbox Worker Loop (Runs every 10s or triggered on-demand) ]
                │
                ▼
[ 1. Query Leasable Events ]
Query: `db.collection('security_outbox')`
Index 1: `(status ASC, nextRetryAt ASC)`
Index 2: `(status ASC, leaseExpiresAt ASC)` (Expired Lease Recovery)
Limit: 50
                │
                ▼
[ 2. Acquire Distributed Lease via Transaction ]
• Sets `status = 'leased'`, `leaseOwner = pod_id`, `leaseExpiresAt = now + 30s`
                │
                ▼
[ 3. Execute Asynchronous Delivery ]
• Idempotent write to `/security_logs/{eventId}`
• Send webhook notifications to tenant endpoints
                │
                ├─────────────────────────────────────────────────┐
                ▼                                                 ▼
       [ Delivery Succeeded ]                            [ Delivery Failed ]
                │                                                 │
    [ 4a. Mark Processed ]                            [ 4b. Handle Failure & Backoff ]
    • `status = 'processed'`                          • Increment `retryCount`
    • `processedAt = now`                             • `backoff = min(300, 2^retries * 5)`s
    • Retained for audit trail                        • `nextRetryAt = now + backoff`
                                                      • If `retries >= 5`: `status = 'dead_letter'`
                                                        Trigger CRITICAL_DLQ_ALERT in Mission Control
```

---

## 8. Comprehensive Acceptance & Failure-Injection Test Evidence

Milestone 1.1 verification strictly separates simulated in-memory verification from live Google Cloud Firestore distributed transaction testing. Both suites pass at **100% compliance (69/69 total tests: 44 in-memory simulation + 25 live Cloud Firestore emulator)**, alongside all 82 passed ecosystem regression tests (151/151 total tests passing).

### 8.1 In-Memory Simulation Suite (`auth/test-milestone-1-1.cjs`): 44/44 PASSED (100.0%)

| Test ID | Test Scenario | Verified Invariant | Status |
| :--- | :--- | :--- | :--- |
| **TC-01** | Completed Code + Wrong PKCE | S256 PKCE verified *before* receipt recovery | ✓ PASS |
| **TC-02** | Concurrent Legitimate Retry | Matching key returns `IN_PROGRESS`; no compromise | ✓ PASS |
| **TC-03** | Concurrent Conflict Redemption | Different key compromises code; revokes session & family | ✓ PASS |
| **TC-04** | Pending Session & Family Inactivity | `checkSession` returns `active: false` for pending | ✓ PASS |
| **TC-05** | Replay Before Finalization | Replay during minting halts finalization; cleans state | ✓ PASS |
| **TC-06** | Replay After Finalization | Active session and family immediately revoked | ✓ PASS |
| **TC-07A** | Stale Worker Fencing | Worker 1 cleans up its OWN pending record | ✓ PASS |
| **TC-07B** | Stale-Worker Safety | Stale worker CANNOT revoke newer worker's active resources | ✓ PASS |
| **TC-08** | Revoked Session API Block | API reads `status === 'revoked'`; rejects with 401 | ✓ PASS |
| **TC-09** | Refresh Against Compromised Family | Refresh grant blocked immediately on revoked family | ✓ PASS |
| **TC-10** | Crash After Finalization | Retried request receives cached encrypted receipt | ✓ PASS |
| **TC-11** | Outbox Worker Lease Recovery | Expired lease claimed by successor worker | ✓ PASS |
| **TC-12** | Dead-Letter Escalation & Redrive | Retries >= 5 escalates to DLQ; manual redrive resets | ✓ PASS |
| **TC-13** | Concurrent Replay Load (10 Keys) | Exactly 1 success (200 OK); 9 rejections | ✓ PASS |
| **TC-14** | Exact Redirect URI Matching | Trailing slash rejected; code remains ISSUED | ✓ PASS |
| **TC-15** | Missing Idempotency Key | Missing header rejected (16-128 chars required) | ✓ PASS |
| **TC-16** | Missing Session or Family | Fails closed; marks COMPROMISED; stages alert | ✓ PASS |
| **TC-17** | Complete Relationship Validation | Detects cross-document link mismatches; fails closed | ✓ PASS |
| **TC-18A** | Expired-Lock Takeover | Matching key safely recovers lease; cleans old pending | ✓ PASS |
| **TC-18B** | Expired-Lock Conflict | Different key triggers compromise/replay defense | ✓ PASS |
| **TC-19** | Firestore Read-Before-Write | All transaction reads strictly precede writes | ✓ PASS |
| **TC-20** | AES-256-GCM Dimensions & AAD | 12-byte IV, 16-byte tag, tampered AAD throws | ✓ PASS |
| **TC-21** | Token Minting Failure Cleanup | Pending session & family revoked on mint failure | ✓ PASS |
| **TC-22** | Receipt Encryption Failure Cleanup | Pending session & family revoked on encryption failure | ✓ PASS |
| **TC-23** | Failure-Handler Fencing | Stale failure handler CANNOT revoke newer worker resources | ✓ PASS |
| **TC-24** | Receipt Key Validation | Fails closed in production on missing, short, or dev keys | ✓ PASS |
| **TC-25** | Multi-Version Receipt Key Rotation | Supports seamless rotation across key versions | ✓ PASS |
| **TC-26** | Fenced Staged Pointer Registration | Stale worker cannot register pointers or overwrite newer worker records | ✓ PASS |
| **TC-27** | Create-Only Document Semantics | Duplicate document creation strictly rejected with ALREADY_EXISTS | ✓ PASS |
| **TC-28** | Strict Fail-Closed Lease Expiration | Missing, invalid, zero, or expired leases fail closed | ✓ PASS |
| **TC-29** | Three-Document Pre-Read Integrity | Reject pointer registration on mismatched or missing staged documents | ✓ PASS |
| **TC-30** | Route Fail-Closed on Missing Capabilities | Missing create() or registerStagedRecords() returns 500 without minting | ✓ PASS |
| **TC-31** | Elimination of Legacy Fallback in /exchange | Missing initiateRedemption returns 500; legacy getCode/markUsed never called | ✓ PASS |
| **TC-32** | Transaction Retry Contention Across Lease Expiration | Contention retry after lease expires fails closed with fresh opTime = Date.now() | ✓ PASS |
| **TC-33** | Granular Staging Failure Cleanup Consistency | Pre-staging, partial staging, and full staging failures clean up exact state | ✓ PASS |
| **TC-34** | Fail-Closed Lease Validation Across All Methods | Non-finite, missing, zero, or negative leases fail closed with COMPROMISED | ✓ PASS |
| **TC-35** | Finalization Code Pointer Validation | Corrupt issuedSessionId / issuedFamilyId fails closed without activating | ✓ PASS |
| **TC-36** | Ambiguous Firestore Create Outcome Handling | safeCleanup revokes committed documents without touching foreign resources | ✓ PASS |
| **TC-37** | Corrupt Lease Metadata Fencing in `initiateRedemption()` | Corrupt lease cannot revoke newer worker, active, or mismatched records | ✓ PASS |
| **TC-38** | Strict Authorization-Code Expiration Validation | Rejects missing, null, malformed, zero, negative, non-finite, and expired timestamps | ✓ PASS |
| **TC-39** | Concurrent-Conflict & Completed-Code Replay Fencing | Protects foreign, newer-worker, and unrelated active records | ✓ PASS |
| **TC-40** | Fail-Closed Replay Fencing & Invalid-Fence Containment | Rejects invalid `fenceToken` values; proves ceremony+lock ownership via `canContainByCeremonyAndLock()`, revokes verified records independently, writes `compromised_ceremonies` tombstone, and verifies `authorizeRefreshGrant()` + receipt key config parity | ✓ PASS |
| **TC-41** | HTTP `POST /oauth/token` Refresh Integration | Exercises real Express `POST /oauth/token` (`grant_type=refresh_token`) across active, revoked family, revoked session, compromised ceremony tombstone, unrelated active ceremony, and missing capability (500 fail-closed) | ✓ PASS |
| **TC-42** | HTTP Refresh-Token Auth, Atomic Rotation, Replay & Concurrency | Verifies SHA-256 constant-time hash comparison (`timingSafeEqualHex`), atomic `currentActiveTokenHash` + `sequenceNumber` rotation, rejection of invalid/cross-family/mismatched/expired tokens, rotated-token replay revocation, and concurrent refresh (1 success / 1 `REFRESH_TOKEN_REPLAY`) | ✓ PASS |

### 8.2 Live Cloud Firestore Emulator Battery (`auth/test-milestone-1-1-emulator.cjs`): 25/25 PASSED (100.0%)

Executed against the official Google Cloud Firestore Java Emulator (`cloud-firestore-emulator-v1.19.8.jar`) on port 8088 in demo mode (`demo-lanzar-id-store-test`):

| Test ID | Test Scenario | Real Firestore Mechanics Verified | Status |
| :--- | :--- | :--- | :--- |
| **EMU-01** | Real Firestore Atomic Code Creation | Persists doc in `/authorization_codes/{codeHash}` with SHA-256 key | ✓ PASS |
| **EMU-02** | Atomic Two-Phase Redemption & GCM Receipt | Full real transaction lifecycle; AES-256-GCM receipt recovery | ✓ PASS |
| **EMU-03** | Stale Worker Revocation Safety | Stale worker fails and CANNOT mutate newer worker's active session | ✓ PASS |
| **EMU-04** | Expired Lock Conflict | Different key transitions live Firestore doc to COMPROMISED | ✓ PASS |
| **EMU-05** | Failure-Handler Fencing Protection | Late exception from old worker blocked from mutating active session | ✓ PASS |
| **EMU-06** | Real Firestore: Same-Key Expired-Lock Takeover | Same-key takeover cleanly revokes old pending records and fences stale worker | ✓ PASS |
| **EMU-07** | Real Firestore: Complete Relationship Validation | Detects and rejects mismatched session tenant; fails closed | ✓ PASS |
| **EMU-08** | Real Firestore: Concurrent Transaction Contention | Handles 10 parallel claims safely with Firestore retry semantics | ✓ PASS |
| **EMU-09** | Real Firestore: Multi-Version Key Rotation | Seamlessly recovers receipt encrypted under earlier key version | ✓ PASS |
| **EMU-10** | Real Firestore: Stale-Worker Fenced Pointer Registration | Stale worker cannot overwrite pointers after takeover; Worker B pointers intact | ✓ PASS |
| **EMU-11** | Real Firestore: Create-Only Document Semantics | Create-only semantics strictly reject duplicate session and family creation | ✓ PASS |
| **EMU-12** | Real Firestore: Strict Fail-Closed Lease Expiration | Missing, zero, invalid, or expired leases fail closed in live Firestore | ✓ PASS |
| **EMU-13** | Real Firestore: Three-Document Pre-Read Integrity | Three-document pre-read integrity rejects missing or mismatched staged docs | ✓ PASS |
| **EMU-14** | Real Firestore: Fail-Closed Protection Against Missing Capabilities | Route fail-closed guard rejects missing capabilities without minting tokens | ✓ PASS |
| **EMU-15** | Real Firestore: Contention Retry After Lease Expiration | Contention retry after lease expiration evaluates fresh opTime and fails closed | ✓ PASS |
| **EMU-16** | Real Firestore: Elimination of Legacy Route Fallback | Route fail-closed guard halts execution on missing initiateRedemption with HTTP 500 | ✓ PASS |
| **EMU-17** | Real Firestore: Fail-Closed Lease Validation Across All Methods | Live Firestore tests for null, 0, negative, malformed string, and non-finite leases | ✓ PASS |
| **EMU-18** | Real Firestore: Finalization Code Pointer Validation | Corrupt code pointers fail closed with RECORD_RELATIONSHIP_MISMATCH; 0 activations | ✓ PASS |
| **EMU-19** | Real Firestore: Ambiguous Firestore Create Outcome Handling | safeCleanup revokes committed documents; stale worker cannot touch active session | ✓ PASS |
| **EMU-20** | Real Firestore: Corrupt Lease Metadata Fencing | Corrupt lease in `initiateRedemption()` cannot revoke newer worker, active, or mismatched docs | ✓ PASS |
| **EMU-21** | Real Firestore: Strict Authorization-Code Expiration | Rejects missing, null, malformed, zero, negative, non-finite, and expired timestamps in live Firestore | ✓ PASS |
| **EMU-22** | Real Firestore: Concurrent-Conflict & Replay Fencing | Protects foreign, newer-worker, and unrelated active records in live Firestore | ✓ PASS |
| **EMU-23** | Real Firestore: Fail-Closed Replay Fencing & Invalid-Fence Containment | Rejects invalid `fenceToken` values; proves ceremony+lock ownership via `canContainByCeremonyAndLock()`, revokes verified records independently, writes `compromised_ceremonies` tombstone, and verifies `authorizeRefreshGrant()` in live Firestore | ✓ PASS |
| **EMU-24** | Real Firestore: HTTP `POST /oauth/token` Refresh Integration | Exercises real Express `POST /oauth/token` (`grant_type=refresh_token`) against live Firestore across active, revoked family, revoked session, compromised ceremony tombstone, and unrelated active ceremony | ✓ PASS |
| **EMU-25** | Real Firestore: HTTP Refresh-Token Auth, Rotation, Replay & Concurrency | Verifies live Firestore `POST /oauth/token` hash auth, atomic `currentActiveTokenHash`/`sequenceNumber` rotation, invalid/cross-family/mismatched/expired rejection, replay revocation, and concurrent refresh (1 success / 1 `REFRESH_TOKEN_REPLAY`) | ✓ PASS |

### 8.3 Refresh-Token Rotation Policy & Bounded Replay-Window Semantics
- **Atomic Authentication & Rotation (`authorizeRefreshGrant()`):** `POST /oauth/token` passes `refreshToken` into `store.authorizeRefreshGrant()`, which validates `lanzar_rt_<familyId>.<seq>.<64-hex>` binding (`TOKEN_FAMILY_MISMATCH` if `family_id` differs), hashes the token with SHA-256 (`hashAuthorizationCode`), and inside `db.runTransaction()` checks `familyData.status`, `sessionData.status`, ownership cross-references, `compromised_ceremonies`, finite future `expiresAt`, and constant-time `timingSafeEqualHex(presentedHash, currentActiveTokenHash)` + `sequenceNumber`. On success, `currentActiveTokenHash`, `sequenceNumber`, and `rotatedTokenHashes` update atomically in the same transaction.
- **Intentional Concurrent Refresh Policy:** Simultaneous requests presenting the same refresh token serialize on `familyRef` inside `db.runTransaction()`. Exactly one commits the rotation (`200`); the second sees `presentedHash` in `rotatedTokenHashes`, triggers `REFRESH_TOKEN_REPLAY` (`401`), and revokes the family/session. This fail-closed single-use policy is intentional because the server cannot cryptographically distinguish a stolen-token race from a legitimate client double-submit race without weakening replay protection. User impact: a concurrent double-refresh requires re-authentication; clients must serialize refresh requests with an in-flight mutex.
- **Bounded 50-Entry `rotatedTokenHashes` Window:** `rotatedTokenHashes` on `token_families/{familyId}` retains the 50 most recent rotated token hashes (`.slice(-50)`). If a token rotated more than 50 rotations ago is reused after eviction, it is still rejected with `401 INVALID_REFRESH_TOKEN` (zero tokens issued), but does **not** trigger `REFRESH_TOKEN_REPLAY` or revoke the active family/session. Milestone 1.1 formally accepts this bounded 50-rotation replay-revocation window to keep family documents bounded without extra per-refresh Firestore reads/writes; durable indefinite history in a subcollection is deferred to a future milestone.

---

## 9. Safe Deployment & Zero-Downtime Rollback Plan

### 9.1 Deployment Procedure
1. Create composite Firestore indexes on `security_outbox` for `(status ASC, nextRetryAt ASC)` and `(status ASC, leaseExpiresAt ASC)`.
2. Deploy updated `store.js` and `server.js` implementing two-phase transactions.
3. Run automated test suites against live staging.
4. Verify `/authorize` creates documents in `/authorization_codes` and `/exchange` executes two-phase redemption.

### 9.2 Safe Rollback Plan (Distributed Compatible)
If a rollback is required:
- Roll back application code to the prior release.
- **Do not revert to the in-memory Map store:** The prior release code will continue reading and writing to `/authorization_codes` via Firestore compatibility adapters.
- In-flight authorization codes remain valid across code rollbacks because they live in Cloud Firestore, not ephemeral process memory.

---

## 10. Definition of Done for Milestone 1.1

- [x] [`auth/auth-backend/store.js`](file:///C:/Users/jonny/.gemini/antigravity/worktrees/lanzar/lanzar_id_main_chat/auth/auth-backend/store.js) contains zero `Map` instances and executes all code mutations in Cloud Firestore.
- [x] Code is stored exclusively as a SHA-256 hash.
- [x] Mandatory `Idempotency-Key` validated on every redemption request (TC-15).
- [x] Strict PKCE validation executed before any idempotent recovery inspection (TC-01).
- [x] Legitimate concurrent retries with matching idempotency keys return `IN_PROGRESS` (TC-02).
- [x] Sessions and token families written as `pending_activation` and atomically activated in finalization transaction (TC-04).
- [x] Finalization verifies lock duration, session existence, family existence, `pending_activation` status, and matching UID/client/ceremony (TC-16, TC-17, TC-18).
- [x] Stale worker revocation safety enforced via `canWorkerRevokeSession` and `canWorkerRevokeFamily` (TC-07B, EMU-03).
- [x] Expired-lock takeover policy implemented: matching key cleanly recovers; differing key compromises (TC-18A, TC-18B, EMU-04).
- [x] Complete circular pointer relationship validation implemented (`session.familyId === issuedFamilyId` and `family.sessionId === issuedSessionId`) (TC-17).
- [x] Failure cleanup handler protected by fencing guards (`handleRedemptionFailure`) (TC-23, EMU-05).
- [x] Immediate durable session and refresh token family revocation committed on compromise across all paths (TC-03, TC-05, TC-06, TC-08, TC-09).
- [x] AES-256-GCM receipt encryption verified with 12-byte IV, 16-byte tag, and AAD context binding (TC-20).
- [x] Dedicated receipt encryption key enforced in production with fail-closed startup validation and multi-version rotation (TC-24, TC-25, EMU-09).
- [x] Complete tenant relationship validation enforced across session and family documents (sessionData.tenantId === codeData.tenantId) (EMU-07).
- [x] Same-key expired lock takeover pre-reads and cleanly revokes old uncommitted records before writes (TC-18A, EMU-06).
- [x] Strengthened ownership predicates validate UID, tenant, client, ceremony, document identity, cross-references, and fencing generation (TC-07B, TC-23, EMU-03, EMU-05).
- [x] Fenced conditional pointer registration enforced on authorization code via registerStagedRecords (TC-26, EMU-10).
- [x] Create-only semantics enforced for pending session and token-family document creation (TC-27, EMU-11).
- [x] Strict fail-closed lease validation enforced across initiateRedemption, registerStagedRecords, and finalizeRedemption (TC-28, TC-34, EMU-12, EMU-17).
- [x] Three-document transactional pre-read integrity enforced in registerStagedRecords (TC-29, EMU-13).
- [x] Security-downgrading fallbacks removed from /exchange route; missing capabilities fail closed (TC-30, EMU-14).
- [x] Distributed capabilities strictly required in /exchange route; legacy fallback eliminated (TC-31, EMU-16).
- [x] Transaction retries evaluate fresh opTime inside callback; contention retries past lease expiration fail closed (TC-32, EMU-15).
- [x] Granular failure cleanup stages accurate session/family parameters with try/catch wrapping (TC-33).
- [x] Strict authorization code pointer validation enforced in finalizeRedemption; corrupt pointers fail closed with RECORD_RELATIONSHIP_MISMATCH (TC-35, EMU-18).
- [x] Ambiguous Firestore create outcomes safely resolved in /exchange by unconditional session and family ID propagation into safeCleanup without touching foreign resources (TC-36, EMU-19).
- [x] Invalid-lease branch in `initiateRedemption()` enforces full fencing and ownership predicates (`canWorkerRevokeSession`, `canWorkerRevokeFamily`) prior to revocation (TC-37, EMU-20).
- [x] Strict authorization-code expiration enforced in `initiateRedemption()` requiring finite, positive `expiresAt` timestamps (TC-38, EMU-21).
- [x] Concurrent-conflict and completed-code replay revocation fenced with `canWorkerRevokeSession`/`canWorkerRevokeFamily` and `canReplayRevokeSession`/`canReplayRevokeFamily` (TC-39, EMU-22).
- [x] Fail-closed replay fencing, invalid-fence ceremony-and-lock containment (`canContainByCeremonyAndLock`), independent per-record revocation, `compromised_ceremonies` tombstone enforcement, and refresh-grant verification verified across missing/corrupt companion and refresh-gate scenarios (TC-40, EMU-23).
- [x] Real HTTP `POST /oauth/token` (`grant_type=refresh_token`) route enforces `codeStore.authorizeRefreshGrant()` with SHA-256 constant-time hash comparison (`timingSafeEqualHex`), atomic `currentActiveTokenHash` + `sequenceNumber` rotation, rotated-token replay revocation, strict identifier/expiration checks, and single-winner concurrent refresh semantics, with no alternate bypass path (TC-41, TC-42, EMU-24, EMU-25).
- [x] All 44 in-memory simulation tests and all 25 live Cloud Firestore Emulator tests pass with 100% compliance (69/69).
- [x] All 82 ecosystem regression tests pass with 100% compliance across Client Registry (9), Auth & MFA (6), Legacy Bridge & SSO (12), and Phase 1 Acceptance (55) (151/151 total tests passing).
- [x] All approved internal LANZAR clients (`portal`, `tickets`, `threadline`, `ai`) log in without regression.
