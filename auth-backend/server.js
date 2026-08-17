require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { initializeApp, cert } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const crypto = require('crypto');
const { AuthorizationCodeStore } = require('./store');
const { getClient } = require('./clients');

const serviceAccount = require('../../firebase-credentials/lanzar-95ae3-firebase-adminsdk-fbsvc-86e8ea5817.json');
initializeApp({
  credential: cert(serviceAccount)
});

const app = express();
app.use(cors());
app.use(express.json());

const codeStore = new AuthorizationCodeStore();

app.post('/authorize', async (req, res) => {
    try {
        const { idToken, client_id, redirect_uri, state, code_challenge, code_challenge_method } = req.body;
        console.log(`[AUTH] Received authorize request for client: ${client_id}`);

        if (!idToken || !client_id || !redirect_uri || !state || !code_challenge || code_challenge_method !== 'S256') {
            return res.status(400).json({ error: 'invalid_request', error_description: 'Missing or invalid parameters' });
        }

        const client = getClient(client_id);
        if (!client || !client.enabled) {
            return res.status(400).json({ error: 'invalid_client', error_description: 'Unknown or disabled client' });
        }
        if (!client.redirectUris.includes(redirect_uri)) {
            return res.status(400).json({ error: 'invalid_request', error_description: 'Unauthorized redirect URI' });
        }

        let decodedToken;
        try {
            decodedToken = await getAuth().verifyIdToken(idToken);
        } catch (e) {
            console.error('[AUTH] Invalid ID token:', e.message);
            return res.status(401).json({ error: 'invalid_grant', error_description: 'Invalid user token' });
        }
        const uid = decodedToken.uid;

        const code = await codeStore.createCode({
            uid,
            clientId: client_id,
            redirectUri: redirect_uri,
            codeChallenge: code_challenge
        });
        console.log(`[AUTH] Generated authorization code for ${uid} -> ${client_id}`);
        res.json({ code, state });
    } catch (error) {
        console.error('[AUTH] Server error during authorize:', error);
        res.status(500).json({ error: 'server_error' });
    }
});

app.post('/exchange', async (req, res) => {
    try {
        const { code, client_id, redirect_uri, code_verifier } = req.body;
        console.log(`[EXCHANGE] Received exchange request for client: ${client_id}`);

        if (!code || !client_id || !redirect_uri || !code_verifier) {
            return res.status(400).json({ error: 'invalid_request' });
        }

        const record = await codeStore.getCode(code);
        if (!record) {
            console.warn('[EXCHANGE] Code not found');
            return res.status(400).json({ error: 'invalid_grant' });
        }
        if (record.used) {
            console.warn(`[EXCHANGE] Attempt to reuse authorization code by ${client_id}`);
            return res.status(400).json({ error: 'invalid_grant' });
        }
        if (Date.now() > record.expiresAt) {
            console.warn(`[EXCHANGE] Expired code used by ${client_id}`);
            return res.status(400).json({ error: 'invalid_grant' });
        }
        if (record.clientId !== client_id || record.redirectUri !== redirect_uri) {
            console.warn('[EXCHANGE] Client ID or Redirect URI mismatch');
            return res.status(400).json({ error: 'invalid_grant' });
        }

        const hash = crypto.createHash('sha256').update(code_verifier).digest('base64url');
        if (hash !== record.codeChallenge) {
            console.warn('[EXCHANGE] PKCE code_challenge mismatch');
            return res.status(400).json({ error: 'invalid_grant' });
        }

        await codeStore.markUsed(code);

        const customToken = await getAuth().createCustomToken(record.uid);
        console.log(`[EXCHANGE] Successfully issued custom token for ${record.uid} -> ${client_id}`);
        res.json({ custom_token: customToken });
    } catch (error) {
        console.error('[EXCHANGE] Server error during exchange:', error);
        res.status(500).json({ error: 'server_error' });
    }
});

const PORT = process.env.PORT || 4001;
app.listen(PORT, () => {
    console.log(`[AUTH-BACKEND] Listening on port ${PORT}`);
});
