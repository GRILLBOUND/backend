require('dotenv').config();
const WebSocket = require('ws');
const { verifyUser } = require('./auth');
const { GameRoom, lobbies } = require('./lobby');
const { validate3DMovement } = require('./security');

const wss = new WebSocket.Server({ port: process.env.PORT || 10000 });

wss.on('connection', (ws) => {
    let session = { auth: false, user: null, lobby: null };

    ws.on('message', async (data) => {
        try {
            const lines = data.toString().split('\n');
            for (const line of lines) {
                if (!line.trim()) continue;
                const msg = JSON.parse(line);

                if (msg.method === 'handshake') {
                    if (msg.app_key !== process.env.APP_SECRET) return ws.close(4003);
                    const { user, error } = await verifyUser(msg.token);
                    if (error) return ws.close(4001);

                    session.auth = true; session.user = user;
                    const rid = msg.project_id || 'main';
                    if (!lobbies.has(rid)) lobbies.set(rid, new GameRoom(rid));
                    session.lobby = lobbies.get(rid);
                    session.lobby.players.set(user.id, { ws, lastPos: {x:0, y:0, z:0}, role: user.role });
                    continue;
                }

                if (!session.auth) return;

                // Admin Commands
                if (msg.method.startsWith('admin_') && session.user.role !== 'admin') return;

                if (msg.method === 'set') {
                    const player = session.lobby.players.get(session.user.id);
                    if (!validate3DMovement(player, msg)) {
                        const axis = msg.name.split('_').pop();
                        return ws.send(JSON.stringify({ method: 'set', name: msg.name, value: player.lastPos[axis] }) + '\n');
                    }
                    session.lobby.broadcast(session.user.id, msg);
                }
            }
        } catch (e) { console.error("Packet Error"); }
    });

    ws.on('close', () => {
        if (session.lobby) session.lobby.players.delete(session.user?.id);
    });
});
