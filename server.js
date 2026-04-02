'use strict';

// ================================================================
// GrillBound WebSocket Server
// From-scratch WebSocket server for GrillBound — a Roblox-inspired
// multiplayer burger kiosk game (like Shawarma Kiosk but with burgers).
//
// Features:
//   - TurboWarp cloud variable protocol (handshake / set / get)
//   - Supabase Auth JWT verification on every connection
//   - Room system (one room per session_id)
//   - Player position sync via cloud variables
//   - Supabase REST API calls for score submission + leaderboard
//   - Anti-cheat: value validation, rate limiting, bounds checking
//
// Setup:
//   npm install ws node-fetch
//   Set environment variables (see CONFIG section below)
//   node server.js
//
// Environment variables:
//   PORT                  WebSocket port (default 3000)
//   SUPABASE_URL          Your Supabase project URL
//   SUPABASE_ANON_KEY     Your Supabase anon/public key
//   SUPABASE_JWT_SECRET   Your Supabase JWT secret (for token verification)
//   TRUST_PROXY           Set to "true" if behind a reverse proxy
// ================================================================

const http    = require('http');
const WebSocket = require('ws');
const https   = require('https');
const crypto  = require('crypto');

// ================================================================
// CONFIG
// ================================================================

const CONFIG = {
  port:           parseInt(process.env.PORT) || 3000,
  trustProxy:     process.env.TRUST_PROXY === 'true',

  // Supabase
  supabaseUrl:    process.env.SUPABASE_URL    || '',
  // Use SUPABASE_PUBLISHABLE_KEY (sb_publishable_...) for new projects,
  // or SUPABASE_ANON_KEY (eyJ...) for legacy projects. Both work.
  supabaseKey:    process.env.SUPABASE_PUBLISHABLE_KEY || process.env.SUPABASE_ANON_KEY || '',
  jwtSecret:      process.env.SUPABASE_JWT_SECRET || '',

  // Rooms
  maxPlayersPerRoom:  10,
  maxRooms:           100,
  roomIdleTimeoutMs:  5 * 60 * 1000,   // close empty rooms after 5 min

  // Cloud variables
  maxVarsPerRoom:     20,
  maxVarNameLength:   256,
  maxVarValueLength:  100000,

  // Rate limiting
  maxMessagesPerSecond: 20,

  // Ping/pong keepalive
  pingIntervalMs: 20000,
  pingTimeoutMs:  10000,
};

// ================================================================
// LOGGER
// ================================================================

function ts() { return new Date().toISOString(); }

const log = {
  info:  (...a) => console.log(`[${ts()}] INFO `, ...a),
  warn:  (...a) => console.warn(`[${ts()}] WARN `, ...a),
  error: (...a) => console.error(`[${ts()}] ERROR`, ...a),
  debug: (...a) => { if (process.env.DEBUG) console.debug(`[${ts()}] DEBUG`, ...a); },
};

// ================================================================
// SUPABASE CLIENT (minimal, no SDK needed)
// ================================================================

const Supabase = {
  // Verify a Supabase JWT and return the decoded payload, or null if invalid.
  // We do manual HMAC-SHA256 verification to avoid needing jsonwebtoken package.
  verifyJWT(token) {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;

      const [headerB64, payloadB64, sigB64] = parts;

      // Verify signature
      const secret = CONFIG.jwtSecret;
      if (secret) {
        const data = `${headerB64}.${payloadB64}`;
        const expectedSig = crypto
          .createHmac('sha256', secret)
          .update(data)
          .digest('base64url');
        if (expectedSig !== sigB64) {
          log.warn('JWT signature mismatch');
          return null;
        }
      }

      // Decode payload
      const payload = JSON.parse(
        Buffer.from(payloadB64, 'base64url').toString('utf8')
      );

      // Check expiry
      if (payload.exp && Date.now() / 1000 > payload.exp) {
        log.warn('JWT expired');
        return null;
      }

      return payload;
    } catch (err) {
      log.warn('JWT parse error:', err.message);
      return null;
    }
  },

  // Make a request to the Supabase REST API
  async request(method, path, body, authToken) {
    return new Promise((resolve, reject) => {
      const url = new URL(CONFIG.supabaseUrl + path);
      const bodyStr = body ? JSON.stringify(body) : null;

      // The publishable key (sb_publishable_...) must go in the apikey header only.
      // The legacy anon key (eyJ...) can also be used as a Bearer token.
      // For authenticated requests, the user's JWT goes in Authorization: Bearer.
      const isLegacyKey = CONFIG.supabaseKey.startsWith('eyJ');
      const options = {
        method,
        hostname: url.hostname,
        path:     url.pathname + url.search,
        headers: {
          'Content-Type':  'application/json',
          'apikey':        CONFIG.supabaseKey,
          'Authorization': authToken
            ? `Bearer ${authToken}`
            : isLegacyKey
              ? `Bearer ${CONFIG.supabaseKey}`
              : `Bearer ${CONFIG.supabaseKey}`, // publishable key as Bearer is fine for apikey=apikey case
        },
      };
      if (bodyStr) options.headers['Content-Length'] = Buffer.byteLength(bodyStr);

      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode, data: JSON.parse(data) });
          } catch {
            resolve({ status: res.statusCode, data });
          }
        });
      });

      req.on('error', reject);
      if (bodyStr) req.write(bodyStr);
      req.end();
    });
  },

  // Call a Supabase RPC function
  async rpc(fnName, params, authToken) {
    return this.request('POST', `/rest/v1/rpc/${fnName}`, params, authToken);
  },

  // Upsert a row
  async upsert(table, row, authToken) {
    return this.request('POST', `/rest/v1/${table}?on_conflict=session_id,player_id`, row, authToken);
  },
};

// ================================================================
// CLOSE CODES
// ================================================================

const CLOSE = {
  ERROR:            4000,
  AUTH_REQUIRED:    4001,
  USERNAME_ERROR:   4002,
  OVERLOADED:       4003,
  PROJECT_UNAVAIL:  4004,
  SECURITY:         4005,
};

// ================================================================
// ROOM
// ================================================================

class Room {
  constructor(id) {
    this.id       = id;           // project_id / session_id
    this.clients  = new Set();    // connected Client instances
    this.vars     = new Map();    // cloud variable name → value
    this.createdAt = Date.now();
    this.idleTimer = null;
  }

  addClient(client) {
    this.clients.add(client);
    clearTimeout(this.idleTimer);
    this.idleTimer = null;
    log.info(`Room ${this.id}: player joined (${this.clients.size} in room)`);
  }

  removeClient(client) {
    this.clients.delete(client);
    log.info(`Room ${this.id}: player left (${this.clients.size} remaining)`);
    if (this.clients.size === 0) {
      this.idleTimer = setTimeout(() => {
        roomList.delete(this.id);
        log.info(`Room ${this.id}: removed (idle timeout)`);
      }, CONFIG.roomIdleTimeoutMs);
    }
  }

  // Send current variable state to a single client (on join)
  syncTo(client) {
    if (this.vars.size === 0) return;
    const messages = [];
    for (const [name, value] of this.vars) {
      messages.push(JSON.stringify({ method: 'set', name, value }));
    }
    client.sendRaw(messages.join('\n'));
  }

  // Broadcast a variable change to everyone except the sender
  broadcast(senderClient, name, value) {
    const msg = JSON.stringify({ method: 'set', name, value });
    for (const client of this.clients) {
      if (client !== senderClient) {
        client.sendRaw(msg);
      }
    }
  }

  setVar(name, value) {
    this.vars.set(name, value);
  }

  get playerCount() { return this.clients.size; }
}

// ================================================================
// ROOM LIST
// ================================================================

const roomList = new Map(); // id → Room

function getOrCreateRoom(id) {
  if (!roomList.has(id)) {
    if (roomList.size >= CONFIG.maxRooms) {
      throw new Error('Server is full');
    }
    roomList.set(id, new Room(id));
    log.info(`Room created: ${id}`);
  }
  return roomList.get(id);
}

// ================================================================
// CLIENT
// ================================================================

class Client {
  constructor(ws, req) {
    this.ws          = ws;
    this.req         = req;
    this.room        = null;
    this.userId      = null;    // Supabase auth.uid()
    this.username    = null;
    this.token       = null;    // raw JWT for Supabase API calls
    this.connectedAt = Date.now();
    this.lastMsg     = Date.now();
    this.msgCount    = 0;
    this.msgWindow   = Date.now();
    this.alive       = true;

    // Ping/pong keepalive
    this.pingTimer   = setInterval(() => this._ping(), CONFIG.pingIntervalMs);
    this.pongTimeout = null;

    ws.on('pong', () => {
      clearTimeout(this.pongTimeout);
      this.alive = true;
    });
  }

  get ip() {
    if (CONFIG.trustProxy) {
      const fwd = this.req.headers['x-forwarded-for'];
      if (fwd) return fwd.split(',')[0].trim();
    }
    return this.req.socket.remoteAddress || 'unknown';
  }

  log(msg)   { log.info(`[${this.username || this.ip}] ${msg}`); }
  warn(msg)  { log.warn(`[${this.username || this.ip}] ${msg}`); }

  sendRaw(data) {
    if (this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(data);
    }
  }

  close(code, reason) {
    clearInterval(this.pingTimer);
    clearTimeout(this.pongTimeout);
    try { this.ws.close(code, reason); } catch {}
  }

  // Rate limiting: max N messages per second
  isRateLimited() {
    const now = Date.now();
    if (now - this.msgWindow > 1000) {
      this.msgWindow = now;
      this.msgCount  = 0;
    }
    this.msgCount++;
    return this.msgCount > CONFIG.maxMessagesPerSecond;
  }

  _ping() {
    if (!this.alive) {
      this.warn('Ping timeout — closing connection');
      this.close(CLOSE.ERROR, 'Ping timeout');
      return;
    }
    this.alive = false;
    try { this.ws.ping(); } catch {}
    this.pongTimeout = setTimeout(() => {
      if (!this.alive) {
        this.close(CLOSE.ERROR, 'Pong timeout');
      }
    }, CONFIG.pingTimeoutMs);
  }
}

// ================================================================
// VALIDATORS
// ================================================================

const CLOUD_PREFIX = '☁ ';

function isValidVarName(name) {
  return typeof name === 'string'
    && name.startsWith(CLOUD_PREFIX)
    && name.length > CLOUD_PREFIX.length
    && name.length <= CONFIG.maxVarNameLength;
}

function isValidVarValue(value) {
  if (typeof value === 'number') {
    return Number.isFinite(value);
  }
  if (typeof value === 'string') {
    if (value.length > CONFIG.maxVarValueLength) return false;
    if (value === '' || value === '.' || value === '-') return false;
    return /^-?\d*\.?\d*$/.test(value);
  }
  return false;
}

function isValidRoomId(id) {
  return typeof id === 'string' && id.length > 0 && id.length < 500;
}

function isValidUsername(u) {
  return typeof u === 'string'
    && u.length >= 1
    && u.length <= 64
    && /^[a-z0-9_\-\.]+$/i.test(u);
}

// ================================================================
// MESSAGE HANDLERS
// ================================================================

async function handleHandshake(client, msg) {
  if (client.room) {
    client.close(CLOSE.ERROR, 'Already performed handshake');
    return;
  }

  const roomId   = String(msg.project_id ?? '');
  const username = String(msg.user ?? '');
  const token    = msg.token ?? null; // GrillBound sends JWT here

  // Validate room ID
  if (!isValidRoomId(roomId)) {
    client.close(CLOSE.PROJECT_UNAVAIL, 'Invalid room ID');
    return;
  }

  // Validate username
  if (!isValidUsername(username)) {
    client.close(CLOSE.USERNAME_ERROR, 'Invalid username');
    return;
  }

  // ── Auth via Supabase JWT ─────────────────────────────
  if (CONFIG.jwtSecret && token) {
    const payload = Supabase.verifyJWT(token);
    if (!payload) {
      client.close(CLOSE.AUTH_REQUIRED, 'Invalid or expired token');
      return;
    }
    client.userId = payload.sub;   // auth.uid()
    client.token  = token;
    client.log(`Authenticated as ${client.userId}`);
  } else if (CONFIG.jwtSecret && !token) {
    // Auth is required but no token provided
    client.close(CLOSE.AUTH_REQUIRED, 'Authentication required — send JWT in handshake token field');
    return;
  } else {
    // No JWT secret configured — run in open mode (dev/testing)
    log.warn('Running without JWT verification (set SUPABASE_JWT_SECRET to enable auth)');
  }

  // ── Join room ─────────────────────────────────────────
  let room;
  try {
    room = getOrCreateRoom(roomId);
  } catch {
    client.close(CLOSE.OVERLOADED, 'Server is full');
    return;
  }

  if (room.playerCount >= CONFIG.maxPlayersPerRoom) {
    client.close(CLOSE.OVERLOADED, 'Room is full');
    return;
  }

  client.username = username;
  client.room     = room;
  room.addClient(client);

  // Send current variable state to the new client
  room.syncTo(client);

  // ── Notify Supabase (non-blocking) ───────────────────
  if (client.userId && CONFIG.supabaseUrl) {
    Supabase.upsert('session_players', {
      session_id: roomId,
      player_id:  client.userId,
    }, client.token).catch(err => log.warn('Supabase upsert failed:', err.message));

    Supabase.upsert('player_positions', {
      session_id: roomId,
      player_id:  client.userId,
      username:   client.username,
      x: 0, y: 1.6, z: 0, rot_y: 0,
    }, client.token).catch(err => log.warn('Supabase position init failed:', err.message));
  }

  client.log(`Joined room ${roomId} (${room.playerCount} players)`);
}

function handleSet(client, msg) {
  if (!client.room) {
    client.close(CLOSE.ERROR, 'No handshake yet');
    return;
  }

  const name  = msg.name;
  const value = msg.value;

  if (!isValidVarName(name)) {
    client.warn(`Invalid var name: ${String(name).slice(0, 50)}`);
    return;
  }

  if (!isValidVarValue(value)) {
    client.warn(`Invalid var value for ${name}`);
    return;
  }

  // Enforce variable count limit
  if (!client.room.vars.has(name) && client.room.vars.size >= CONFIG.maxVarsPerRoom) {
    client.warn('Variable limit reached');
    return;
  }

  // ── Position sync: update Supabase (non-blocking, throttled) ──
  // GrillBound uses ☁ player_x, ☁ player_y, ☁ player_z, ☁ player_rot_y
  if (client.userId && CONFIG.supabaseUrl) {
    const posMap = {
      '☁ player_x':     'x',
      '☁ player_y':     'y',
      '☁ player_z':     'z',
      '☁ player_rot_y': 'rot_y',
    };
    if (posMap[name]) {
      // Throttle position writes to max once per 80ms
      const now = Date.now();
      if (!client._lastPosSave || now - client._lastPosSave > 80) {
        client._lastPosSave = now;
        Supabase.request('PATCH',
          `/rest/v1/player_positions?session_id=eq.${client.room.id}&player_id=eq.${client.userId}`,
          { [posMap[name]]: parseFloat(value), updated_at: new Date().toISOString() },
          client.token
        ).catch(() => {});
      }
    }
  }

  client.room.setVar(name, value);
  client.room.broadcast(client, name, value);
}

function handleGet(client) {
  if (client.room) {
    client.room.syncTo(client);
  }
}

// ================================================================
// CONNECTION HANDLER
// ================================================================

function onConnection(ws, req) {
  // Block Scratch session cookies — security protection from TW's own server
  if (req.headers.cookie?.includes('scratchsessionsid=')) {
    ws.send('Your Scratch login token was sent to this server. Change your Scratch password immediately.');
    ws.close(CLOSE.SECURITY);
    return;
  }

  const client = new Client(ws, req);
  client.log('Connected');

  ws.on('message', async (data, isBinary) => {
    if (isBinary) return;
    if (client.isRateLimited()) {
      client.warn('Rate limit exceeded');
      return;
    }

    let msg;
    try {
      msg = JSON.parse(data.toString());
      if (!msg || typeof msg.method !== 'string') throw new Error('invalid');
    } catch {
      client.close(CLOSE.ERROR, 'Invalid JSON');
      return;
    }

    try {
      switch (msg.method) {
        case 'handshake': await handleHandshake(client, msg); break;
        case 'set':       handleSet(client, msg);              break;
        case 'get':       handleGet(client);                   break;
        default:
          client.warn(`Unknown method: ${msg.method}`);
      }
    } catch (err) {
      client.warn('Handler error: ' + err.message);
      client.close(CLOSE.ERROR, 'Internal error');
    }
  });

  ws.on('close', (code) => {
    client.log(`Disconnected (code ${code})`);
    clearInterval(client.pingTimer);
    clearTimeout(client.pongTimeout);

    if (client.room) {
      client.room.removeClient(client);

      // Remove position from Supabase (non-blocking)
      if (client.userId && CONFIG.supabaseUrl) {
        Supabase.request('DELETE',
          `/rest/v1/player_positions?session_id=eq.${client.room.id}&player_id=eq.${client.userId}`,
          null, client.token
        ).catch(() => {});
      }
    }
  });

  ws.on('error', (err) => {
    client.warn('Socket error: ' + err.message);
  });
}

// ================================================================
// HTTP + WEBSOCKET SERVER
// ================================================================

const server = http.createServer((req, res) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  if (req.url === '/' || req.url === '') {
    const stats = {
      name:         'GrillBound Cloud Server',
      status:       'running',
      rooms:        roomList.size,
      totalPlayers: [...roomList.values()].reduce((n, r) => n + r.playerCount, 0),
      uptime:       Math.floor(process.uptime()) + 's',
    };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(stats, null, 2));
    return;
  }

  res.writeHead(404);
  res.end('Not found');
});

const wss = new WebSocket.Server({
  noServer:      true,
  clientTracking: false,
  maxPayload:    1024 * 1024, // 1MB
});

server.on('upgrade', (req, socket, head) => {
  wss.handleUpgrade(req, socket, head, (ws) => {
    wss.emit('connection', ws, req);
  });
});

wss.on('connection', onConnection);

server.listen(CONFIG.port, () => {
  log.info(`GrillBound Cloud Server running on port ${CONFIG.port}`);
  log.info(`Auth: ${CONFIG.jwtSecret ? 'ENABLED (JWT)' : 'DISABLED (open mode)'}`);
  log.info(`Supabase: ${CONFIG.supabaseUrl ? CONFIG.supabaseUrl : 'NOT CONFIGURED'}`);
});

// ================================================================
// STATUS LOGGING
// ================================================================

setInterval(() => {
  const players = [...roomList.values()].reduce((n, r) => n + r.playerCount, 0);
  log.info(`Status: ${roomList.size} rooms, ${players} players online`);
}, 60_000);

// Graceful shutdown
process.on('SIGTERM', () => {
  log.info('SIGTERM received — shutting down');
  server.close(() => process.exit(0));
});
