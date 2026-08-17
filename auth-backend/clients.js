const clients = {
    'portal': {
        id: 'portal',
        redirectUris: [
            'http://localhost:5173/',
            'https://portal.lanzar.me/',
            'http://localhost:8000/',
            'http://localhost:8000'
        ],
        enabled: true
    },
    'tickets': {
        id: 'tickets',
        redirectUris: [
            'http://localhost:5174/',
            'https://tickets.lanzar.me/'
        ],
        enabled: true
    },
    'threadline': {
        id: 'threadline',
        redirectUris: [
            'http://localhost:5175/',
            'https://threadline.lanzar.me/',
            'https://threadline-production-1c28.up.railway.app/'
        ],
        enabled: true
    }
};
function getClient(clientId) { return clients[clientId]; }
module.exports = { getClient };
