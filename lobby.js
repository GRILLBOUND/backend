const WebSocket = require('ws');

class GameRoom {
    constructor(id) {
        this.id = id;
        this.players = new Map(); // UUID -> { ws, lastPos, role }
    }

    broadcast(senderId, msg, isGlobal = false) {
        const packet = JSON.stringify({ ...msg, sender: senderId }) + '\n';
        this.players.forEach((p, id) => {
            if ((isGlobal || id !== senderId) && p.ws.readyState === WebSocket.OPEN) {
                p.ws.send(packet);
            }
        });
    }
}

module.exports = { GameRoom, lobbies: new Map() };
