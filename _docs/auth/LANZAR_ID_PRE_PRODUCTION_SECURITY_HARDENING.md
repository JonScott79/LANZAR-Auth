# LANZAR ID — Pre-Production Security Hardening Milestone
**Document ID:** LID-SEC-MILESTONE-002  
**Classification:** Confidential — Internal Security Milestone Directive  
**Status:** Active Tracking Milestone (Formally Established)  
**Date:** November 10, 2026  
**Branch:** `lanzar_id_main_chat`  
**Accepted Baseline Commit:** `62d2df807352377c86570c9ec3bb3bb2816911c4`  

---

## 1. Executive Summary & Milestone Boundary

The **Priority 1 Security Remediation** has been formally accepted and closed based on independent, read-only source-code verification (documented in [`LANZAR_ID_PRIORITY1_FINAL_VERIFICATION_REPORT.md`](file:///C:/Users/jonny/.gemini/antigravity/brain/181f70b2-f3a3-4005-b91d-fd091daec5b7/LANZAR_ID_PRIORITY1_FINAL_VERIFICATION_REPORT.md)).

### Formally Closed Priority 1 Findings

| ID | Description | Resolution Status | Verified Commit |
|---|---|:---:|:---:|
| **LID-SEC-004** | Mandatory LANZAR ID `session_id` claim, UID binding, and session status enforcement | **CLOSED** | `62d2df8` |
| **LID-SEC-002** | Application-level rate limiting on OAuth, MFA, and phone OTP routes | **CLOSED (Local)** | `62d2df8` |
| **LID-SEC-005** | Elimination of static dev MFA HMAC fallback; strict $\ge 32$-byte validation | **CLOSED** | `62d2df8` |

Authoritative session storage consistency at `/users/{uid}/sessions/{sessionId}` is confirmed across all lifecycle components and Firestore security rules. Test suite integrity was reviewed with 197/197 passing tests and zero assertions weakened or removed.

---

## 2. Milestone: Pre-Production Security Hardening

This separate milestone tracks all outstanding security, architectural resilience, and deployment-readiness requirements identified during the security audit and verification phases. 

> [!IMPORTANT]
> These findings are explicitly **NOT** part of the completed Priority 1 milestone. They represent prerequisites for eventual staging and production cloud deployment. Passing local tests does not constitute production certification.

### Register of Outstanding Findings

| ID | Finding | Severity | Category | Target Scope |
|---|---|:---:|:---:|---|
| **LID-VER-001** | Rate-limiter `Map` lacks an upper maximum entry bound (`MAX_ENTRIES`) | Low | Memory Management | `rateLimiter.js` |
| **LID-VER-002** | Account-only MFA throttling permits targeted account lockout | Medium | Abuse Resistance | `rateLimiter.js`, `/mfa/verify` |
| **LID-VER-003** | Express reverse-proxy trust configuration is not defined (`trust proxy`) | Medium | Network / Proxy | `app.js` |
| **LID-VER-004** | Server startup does not invoke `bootstrap()` validation before traffic | High | Fail-Closed Lifecycle | `server.js`, `bootstrap.js` |
| **LID-VER-005** | Missing `APP_ENV` can cause development environment defaulting | Medium | Configuration Hygiene | `mfaService.js` |
| **LID-SEC-001** | Authorization-code storage is process-local (`Map`) | High | Distributed Architecture | Multi-instance clustering |
| **LID-SEC-003** | Session-cache invalidation is process-local (`Map`) | Medium | Distributed Architecture | Multi-instance clustering |

---

## 3. Detailed Finding Profiles & Analysis

### 3.1 LID-VER-001: Rate-Limiter Upper Memory Bounding
* **Location:** `auth/auth-backend/middleware/rateLimiter.js`
* **Current State:** The in-memory `rateLimitStore` Map runs a periodic sweep every 60 seconds to prune expired buckets. However, there is no hard cap on the number of concurrent keys stored.
* **Risk:** An adversary generating hundreds of thousands of requests with spoofed IPs could inflate heap memory between cleanup cycles, creating memory pressure.
* **Remediation Specification:** Implement a hard entry cap (e.g., `MAX_ENTRIES = 10,000`) with an LRU eviction or FIFO drop policy if the store reaches capacity under load.

### 3.2 LID-VER-002: Dual-Key MFA Throttling
* **Location:** `auth/auth-backend/middleware/rateLimiter.js` (rule `mfa_verify`)
* **Current State:** Failed MFA attempts are keyed solely by target `uid` (`mfa_fail:${method}:${uid}`).
* **Risk:** An attacker possessing a victim's password could deliberately submit 5 incorrect TOTP/SMS codes to lock the legitimate user out of their account for 15 minutes.
* **Remediation Specification:** Redesign MFA rate limiting to enforce a dual-key strategy: throttle primarily by client IP (`mfa_fail:${method}:${ip}`) with tighter limits, and apply looser, graduated backoff on the account (`uid`) with alerting and step-up challenge rather than an immediate complete account lockout.

### 3.3 LID-VER-003: Reverse-Proxy IP Trust Configuration
* **Location:** `auth/auth-backend/app.js`
* **Current State:** Express `trust proxy` setting is not configured.
* **Risk:** In local development, `req.ip` reflects direct socket connections (`127.0.0.1`). When deployed behind a cloud reverse proxy (Google Cloud Load Balancer, Railway, Cloudflare), `req.ip` defaults to the internal proxy socket address, causing all client requests to share a single rate-limit bucket. Conversely, trusting `X-Forwarded-For` globally without specifying trusted subnets permits client-side IP spoofing.
* **Remediation Specification:** Establish an explicit, environment-aware `trust proxy` configuration (e.g., `app.set('trust proxy', 'loopback, linklocal, uniquelocal')` or provider-specific CIDR blocks) when moving toward cloud staging.

### 3.4 LID-VER-004: Fail-Closed Process Startup Validation
* **Location:** `auth/auth-backend/server.js` & `bootstrap.js`
* **Current State:** `server.js` imports helper `isLoopbackEndpoint` but does not invoke `bootstrap(process.env)` before listening on the port.
* **Risk:** Critical environment validations (e.g., `MFA_HMAC_SECRET` presence and length $\ge 32$ bytes) execute lazily when the first token signing request arrives. In a misconfigured staging/production deployment, the server starts, reports healthy to load balancers, and serves 500 errors to users upon login.
* **Remediation Specification:** Invoke `bootstrap(process.env)` synchronously in `server.js` prior to calling `app.listen()`. The process must terminate immediately (`process.exit(1)`) on bootstrap failure.

### 3.5 LID-VER-005: Environment Derivation Hardening
* **Location:** `auth/auth-backend/services/mfaService.js:19`
* **Current State:** Environment resolution uses `const env = process.env.APP_ENV || 'development'`.
* **Risk:** If a staging or production container sets standard `NODE_ENV=production` but omits `APP_ENV`, the service defaults to `'development'`, allowing insecure dev fallbacks.
* **Remediation Specification:** Normalize environment derivation across all services:
  ```javascript
  const env = process.env.APP_ENV || (process.env.NODE_ENV === 'production' ? 'production' : 'development');
  ```
  Ensure any production indicator strictly disables development assumptions.

### 3.6 LID-SEC-001 & LID-SEC-003: Distributed Architecture Resilience
* **Scope:** Multi-instance clustering and horizontal scaling.
* **LID-SEC-001 (High):** OAuth authorization codes are held in a process-local Node.js `Map` (`auth/auth-backend/routes/oauth.js`). If `/authorize` and `/exchange` hit different container instances behind a round-robin load balancer, code exchange fails with `invalid_grant`.
* **LID-SEC-003 (Medium):** The in-memory session revocation cache (`auth/auth-backend/services/centralSessionService.js`) caches session validity for 60 seconds per process. In a multi-instance deployment, revoking a session on Instance A leaves the cache active on Instance B until the 60s TTL expires.
* **Archived Mandate:** Findings LID-SEC-001 and LID-SEC-003 **must remain prominently visible**. They cannot be deferred, suppressed, or marked as closed while the backend uses process-local memory. Multi-instance deployment requires distributed storage (Cloud Firestore transactions or Redis/Valkey with Pub/Sub invalidation).

---

## 4. Required Future Work Checklist

1. [ ] **Rate Limiter Memory Bounds:** Add bounded LRU/FIFO capacity limits to `rateLimiter.js`.
2. [ ] **MFA Throttling Redesign:** Combine account (`uid`) and client IP controls to mitigate targeted account-lockout DoS.
3. [ ] **Reverse-Proxy Configuration:** Configure Express `trust proxy` with explicit trusted CIDR/hop definitions for target hosting environments.
4. [ ] **Fail-Closed Startup Bootstrapping:** Integrate synchronous `bootstrap()` execution into `server.js` before accepting inbound network traffic.
5. [ ] **Environment Resolution Hygiene:** Enforce fail-closed `APP_ENV` / `NODE_ENV` derivation across all backend services.
6. [ ] **Distributed Code Storage (LID-SEC-001):** Implement atomic, shared authorization-code persistence for multi-instance operation.
7. [ ] **Distributed Session Invalidation (LID-SEC-003):** Implement shared session revocation messaging across cluster nodes.

---

## 5. Deployment Readiness Policy & Boundaries

All existing project governance directives remain in strict effect:

* **No Production Deployment:** Production systems remain untouched.
* **No Staging Deployment:** Cloud staging is deferred until pre-production hardening is complete.
* **No Cloud Provisioning:** Zero cloud infrastructure, databases, or cloud IAM roles may be provisioned.
* **No Paid Services or Infrastructure:** Operating budget remains at $\$0.00$.
* **No SMS Activation:** SMS provider integration remains simulated via `MockSMSProvider`.
* **No OAuth Additions:** No client IDs, redirect URIs, or domain registrations may be added to cloud providers.
* **No Branch Merging:** No merge into `main` (`e309c26250bba14d36824de3d073bec26c81dbf4` remains untouched).
* **Local Development Isolation:** All development, testing, and validation remain strictly confined to the local Firebase emulators and loopback addresses.

Passing local regression tests is a prerequisite for milestone progress, but **does not constitute production certification**.

---

## 6. Document Cross-References

* **Priority 1 Verification Report:** [`LANZAR_ID_PRIORITY1_FINAL_VERIFICATION_REPORT.md`](file:///C:/Users/jonny/.gemini/antigravity/brain/181f70b2-f3a3-4005-b91d-fd091daec5b7/LANZAR_ID_PRIORITY1_FINAL_VERIFICATION_REPORT.md)
* **Priority 1 Remediation Report:** [`LANZAR_ID_PRIORITY1_REMEDIATION_REPORT.md`](file:///C:/Users/jonny/.gemini/antigravity/brain/181f70b2-f3a3-4005-b91d-fd091daec5b7/LANZAR_ID_PRIORITY1_REMEDIATION_REPORT.md)
* **Comprehensive Security Audit Report:** [`LANZAR_ID_SECURITY_AUDIT_REPORT.md`](file:///C:/Users/jonny/.gemini/antigravity/brain/181f70b2-f3a3-4005-b91d-fd091daec5b7/LANZAR_ID_SECURITY_AUDIT_REPORT.md)
* **Master Security Directive:** [`_docs/auth/LANZAR_ID_SECURITY_MODEL.md`](file:///C:/Users/jonny/.gemini/antigravity/worktrees/lanzar/lanzar_id_main_chat/_docs/auth/LANZAR_ID_SECURITY_MODEL.md)
