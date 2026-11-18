# LANZAR ID — Account Preservation & Migration Plan

**Date:** 2026-11-18  
**Core Rule:** Existing users must never lose access, subscriptions, roles, or application data. Accounts are **never** merged by email address alone without verified credential/ownership proof.

---

## 1. Per-Application Identity & Foreign-Key Map

| Application | Primary User Key | Foreign Keys / Owned Data | Preservation Strategy |
|---|---|---|---|
| **LANZAR Portal** | Firebase `uid` | `users/{uid}.accountId` → `accounts/{accountId}`, `admins/{uid}` | Central LANZAR ID mints custom tokens for the user's exact Firebase `uid`. Zero data migration required. |
| **LANZAR Tickets** | Firebase `uid` | `tickets/*` (`authUid`, `customerId`, `userId`, `accountId`), `customers/{uid}.stripeCustomerId`, `admins/{uid}` | Preserve exact Firebase `uid` via LANZAR ID PKCE + `signInWithCustomToken`. Fix `customers.js` auto-provisioning and align `customerUid` → `authUid` on claimed tickets. |
| **Threadline** | Firebase / OIDC `sub` (`uid`) | SQLite `threadlines.owner_id`, `imports.owner_id`, `saved_segments.owner_id` | Preserve existing `JON_CANONICAL_UID` + `JON_LEGACY_UIDS` (`getAuthorizedUids`) delegation in `backend/services/threadlines.js`; no SQLite migration needed. |
| **LANZAR AI** | `uid` (`sub`) | `AI/data/user-profiles.json`, `user-memories.json`, `conversations.json` (`userId`) | OIDC `sub` / Firebase `uid` maps directly to `userId`. Legacy `user_*` local dev files stay untouched unless explicitly linked. |
| **Pythos** | Dual: Firebase `uid` vs `lanzar_<sha256(email)>` | `pythos/app/lanzar_id_accounts/{uid}`, `users/{uid}.pythosLegacyUid`, `users/{uid}/pythos_chats`, `pythos_memory`, `pythos_learning` | **Explicit Verified Linking Only:** `auth-backend` `POST /login/legacy-bridge` verifies the user's actual `scrypt` password before issuing a Firebase Auth session and storing `pythosLegacyUid`. Pythos backend must wire `resolveCanonicalIdentity()` to read `pythos_memory` / `pythos_learning` across `[uid, pythosLegacyUid]`, and stop overwriting passwords bidirectionally. |

---

## 2. Rollback & Safety Rules

- **No Destructive Production Migrations:** Never delete `customers/{uid}`, `pythos/app/lanzar_id_accounts/{uid}`, or SQLite legacy `owner_id` aliases during rollout.
- **Explicit Ownership Proof:** Pythos `scrypt` → LANZAR ID migration requires `scrypt` password verification (`POST /login/legacy-bridge`) or authenticated dual-proof linking (`POST /api/auth/lanzar/link-google`).
- **Approval Gate:** Any production user-data backfill or Pythos/Tickets production promotion requires Jon's explicit sign-off.
