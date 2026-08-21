const clients = {
    'portal': {
        id: 'portal',
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
    'tickets': {
        id: 'tickets',
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
        redirectUris: [
            'http://localhost:3005',
            'http://localhost:3005/',
            'https://pythos.lanzar.me',
            'https://pythos.lanzar.me/'
        ],
        enabled: true
    }
};
function getClient(clientId) { return clients[clientId]; }
module.exports = { getClient };
