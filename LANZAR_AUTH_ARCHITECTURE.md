# LANZAR Auth Hub Architecture

## 1. Current Architecture
The LANZAR ecosystem currently consists of multiple distinct front-end applications (Portal, Tickets, Threadline). Right now, they either implement independent Firebase authentication or rely on mock logins. The Auth Hub (uth.lanzar.me) is being introduced as the central identity provider (IdP) for all LANZAR properties, establishing a Single Sign-On (SSO) experience. It bridges the frontend React applications using a secure, custom OAuth 2.0 / PKCE flow backed by a dedicated Node.js/Express backend (uth-backend).

## 2. Firebase Project Relationships
**CRITICAL FINDING:** uth.lanzar.me, portal.lanzar.me, and 	ickets.lanzar.me all currently share the exact same Firebase project (lanzar-95ae3). 

Because they share the same project, Custom Token exchange is natively supported without needing to cross project boundaries or configure Google Cloud IAM permissions for multi-project token signing. The Firebase Admin SDK in the Auth Backend can generate custom tokens that are immediately valid for all LANZAR client applications.

## 3. Auth Flow
1. **Initiation:** Unauthenticated user visits a LANZAR property (e.g., portal.lanzar.me).
2. **Redirect:** The property redirects the user to uth.lanzar.me with client_id, edirect_uri, state, code_challenge, and code_challenge_method=S256.
3. **Authentication:** User logs in at uth.lanzar.me via Firebase Auth (Google/Email).
4. **Code Generation:** The Auth frontend sends the user's Firebase ID token and the request parameters to the Auth Backend.
5. **Authorization:** The Backend verifies the ID token, validates the client/redirect, stores the authorization code (bound to PKCE and user), and returns the code to the frontend.
6. **Callback:** Auth frontend redirects the user back to the originating property's edirect_uri with code and state.
7. **Exchange:** The originating property receives the code, verifies the state, and sends the code and code_verifier to the Auth Backend.
8. **Token Issue:** The Auth Backend verifies the code and PKCE, marks the code as used, generates a Firebase Custom Token, and returns it.
9. **Sign-In:** The property uses signInWithCustomToken(token) to establish its local Firebase session.

## 4. PKCE Flow
Because LANZAR properties are Single Page Applications (SPAs) incapable of securely storing a client_secret, we implement Proof Key for Code Exchange (PKCE).
- **Client (Portal/Tickets):** Generates a random code_verifier. Hashes it using SHA-256 to create the code_challenge. Sends the challenge during the initial redirect.
- **Backend:** Stores the code_challenge alongside the authorization code.
- **Client:** Sends the original plain-text code_verifier during the token exchange.
- **Backend:** Hashes the code_verifier and confirms it matches the stored code_challenge before issuing the Custom Token. This prevents authorization code interception attacks.

## 5. Client Registry
The Auth Backend maintains a registry of authorized clients.
- client_id: Unique identifier (e.g., portal, 	ickets, 	hreadline).
- llowed_redirect_uris: Strict list of permitted callback URLs.
- status: Active/Disabled.
The backend independently validates every incoming edirect_uri against this registry. It never blindly trusts the URI provided by the frontend.

## 6. Authorization Code Lifecycle
Authorization codes are:
- Cryptographically random (e.g., 32+ bytes of entropy, hex/base64 encoded).
- Short-lived (expires in 60 seconds).
- Single-use (enforced by the backend database).
- Opaque (contains no embedded user data or JWTs).
- Tightly bound to the client_id, edirect_uri, code_challenge, and specific uid.

## 7. Token Exchange
Endpoint: POST /exchange
The backend strictly verifies:
1. Code exists, is unexpired, and used === false.
2. client_id and edirect_uri match the original authorization request exactly.
3. The SHA-256 hash of code_verifier matches the stored code_challenge.
Upon success, the code is immediately flagged as used=true (or deleted) to prevent replay attacks.

## 8. Firebase Custom Token Handling
The Auth Backend uses the Firebase Admin SDK (dmin.auth().createCustomToken(uid)) to generate the token. 
- Firebase Admin credentials (service accounts) are strictly isolated to the Node.js backend. 
- Custom tokens are only passed securely over HTTPS back to the requesting client during the exchange step.
- The receiving app consumes the token using the Firebase Client SDK.

## 9. Session Behavior
There is **no shared browser storage** (localStorage, sessionStorage, or IndexedDB) between portal.lanzar.me, 	ickets.lanzar.me, and uth.lanzar.me. 
The Auth Hub acts solely as the identity bridge. Once a client application completes the flow and calls signInWithCustomToken(), it manages its own isolated Firebase session. If the user refreshes portal.lanzar.me, Firebase automatically restores the session from the Portal's own IndexedDB.

## 10. Logout Behavior
When a user clicks "Logout" in a client application (e.g., Portal):
1. The app clears its local Firebase session (signOut(auth)).
2. The app redirects the user to uth.lanzar.me/logout?redirect_uri=...
3. The Auth Hub clears its own central Firebase session.
4. The Auth Hub redirects the user back to the client application (which is now completely signed out).
*Note: This logs the user out of the central Hub, but does not actively kill sessions on other previously authenticated LANZAR apps.*

## 11. Error Handling
The backend implements standardized, secure error responses:
- **Client/Redirect Mismatch:** Returns standard OAuth invalid_request or invalid_client.
- **Expired/Reused Code:** Returns invalid_grant.
- **PKCE Failure:** Returns invalid_grant.
Errors are generic externally to prevent information leakage (e.g., "Invalid or expired code"), while detailed telemetry is written to server logs.

## 12. Security Considerations
- **State Parameter:** Mitigates CSRF attacks. The client must generate a secure random state and verify it upon return before attempting to exchange the code.
- **Strict Redirect URIs:** Prevents open-redirect and authorization code theft.
- **Token Verification:** The backend never trusts the browser's claim of identity. It extracts the uid directly from the cryptographically verified Firebase ID Token provided during the authorization step.

## 13. Development vs Production Differences
- **Code Storage:** For initial development, an in-memory store (AuthorizationCodeStore class) will be used to hold active authorization codes. For production, this interface will be swapped with a persistent store (e.g., Redis or Firestore).
- **CORS/Cookies:** Development relies on localhost origins which must be explicitly whitelisted in the CORS configuration and Client Registry. Production will restrict to *.lanzar.me.
