const clients = {
    'portal': {
        id: 'portal',
        redirectUris: [
            'http://localhost:5173/callback',
            'https://portal.lanzar.me/callback',
            'http://localhost:8000/',
            'http://localhost:8000'
        ],
        enabled: true
    }
};
function getClient(clientId) { return clients[clientId]; }
module.exports = { getClient };
