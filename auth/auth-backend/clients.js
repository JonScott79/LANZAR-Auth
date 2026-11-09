// clients.js
// Authorized OAuth 2.0 / PKCE client registry for LANZAR ecosystem

const isProduction = process.env.NODE_ENV === 'production';

const clients = {
    'portal': {
        id: 'portal',
        name: 'LANZAR Portal & Mission Control',
        redirectUris: [
            'http://localhost:5173',
            'http://localhost:5173/',
            'http://localhost:3000',
            'http://localhost:3000/',
            'http://localhost:8000',
            'http://localhost:8000/',
            'https://portal.lanzar.me',
            'https://portal.lanzar.me/'
        ],
        enabled: true
    },
    'id': {
        id: 'id',
        name: 'LANZAR ID Central Account Hub',
        redirectUris: [
            'http://localhost:5177',
            'http://localhost:5177/',
            'http://localhost:3000',
            'http://localhost:3000/',
            'https://id.lanzar.me',
            'https://id.lanzar.me/'
        ],
        enabled: true
    },
    'mothership': {
        id: 'mothership',
        name: 'LANZAR Mothership Gateway',
        redirectUris: [
            'http://localhost:5178',
            'http://localhost:5178/',
            'http://localhost:8888',
            'http://localhost:8888/',
            'https://lanzar.me',
            'https://lanzar.me/'
        ],
        enabled: true
    },
    'tickets': {
        id: 'tickets',
        name: 'LANZAR Tickets & Support Queue',
        redirectUris: [
            'http://localhost:5174',
            'http://localhost:5174/',
            'http://localhost:3000',
            'http://localhost:3000/',
            'http://localhost:5173',
            'http://localhost:5173/',
            'https://tickets.lanzar.me',
            'https://tickets.lanzar.me/'
        ],
        enabled: true
    },
    'threadline': {
        id: 'threadline',
        name: 'LANZAR Threadline Intelligence',
        redirectUris: [
            'http://localhost:5175',
            'http://localhost:5175/',
            'https://threadline.lanzar.me',
            'https://threadline.lanzar.me/',
            'https://threadline-production-1c28.up.railway.app',
            'https://threadline-production-1c28.up.railway.app/'
        ],
        enabled: true
    },
    'pythos': {
        id: 'pythos',
        name: 'Pythos AI Autonomous Tutor',
        redirectUris: [
            'http://localhost:3005',
            'http://localhost:3005/',
            'https://pythos.lanzar.me',
            'https://pythos.lanzar.me/'
        ],
        enabled: true
    },
    'ai': {
        id: 'ai',
        name: 'LANZAR AI Platform',
        redirectUris: [
            'http://localhost:5176',
            'http://localhost:5176/',
            'https://ai.lanzar.me',
            'https://ai.lanzar.me/'
        ],
        enabled: true
    }
};

function getClient(clientId) {
    const client = clients[clientId];
    if (!client) return null;

    // In production, strictly enforce HTTPS and strip localhost redirect destinations
    if (isProduction) {
        return {
            ...client,
            redirectUris: client.redirectUris.filter(uri => !uri.startsWith('http://localhost') && !uri.startsWith('http://127.0.0.1'))
        };
    }
    return client;
}

module.exports = { getClient, clients };
