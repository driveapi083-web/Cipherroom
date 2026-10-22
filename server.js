// CipherRoom server.
//
// The server is intentionally "dumb": it relays and holds opaque ciphertext, in
// memory only. It never receives the room password or any encryption key. Clients
// prove they know the password by sending a value derived from it (`auth`), of
// which the server only keeps a SHA-256 hash.
//
// Who may enter:
//   - the host (holds a secret host token),
//   - guests with a personal one-time invite ticket. A ticket admits its owner once;
//     after they leave, coming back needs the host's permission ("knock").

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Store, isValidId } from './src/store.js';
import { RateLimiter } from './src/ratelimit.js';
import { acceptUpgrade, READY } from './src/websocket.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, 'public');

const MB = 1024 * 1024;
const MIN_ITERATIONS = 600_000;
const MAX_ITERATIONS = 5_000_000;
const MAX_CIPHERTEXT_CHARS = 16_384;
const MAX_HELLO_CHARS = 600;
const MAX_CHUNKS = 170; // 10 MB / 64 KB, rounded up with a little slack
const MAX_CHUNK_CT_CHARS = 87_500; // 64 KB + tag, base64url
const MAX_WS_PAYLOAD = 100 * 1024;
const MAX_TICKETS = 30;
const MAX_KNOCKS = 10;
const KNOCK_TIMEOUT_MS = 5 * 60_000;
const MAX_CONNECTIONS_PER_IP = 30;

const B64U = /^[A-Za-z0-9_-]+$/;
const isB64u = (s, len) => typeof s === 'string' && s.length === len && B64U.test(s);
const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');
const matchesHash = (secret, hashHex) => {
  const a = Buffer.from(sha256hex(secret), 'hex');
  const b = Buffer.from(String(hashHex), 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};
const validHello = (h) =>
  !!h && isB64u(h.iv, 16) && typeof h.ct === 'string' && h.ct.length >= 22 && h.ct.length <= MAX_HELLO_CHARS && B64U.test(h.ct);
const num = (v, fallback) => (v !== undefined && v !== '' && Number.isFinite(Number(v)) ? Number(v) : fallback);

const STATIC_FILES = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
  '/crypto.js': ['crypto.js', 'text/javascript; charset=utf-8'],
  '/integrity.js': ['integrity.js', 'text/javascript; charset=utf-8'],
  '/style.css': ['style.css', 'text/css; charset=utf-8'],
  '/favicon.svg': ['favicon.svg', 'image/svg+xml'],
  '/manifest.webmanifest': ['manifest.webmanifest', 'application/manifest+json'],
  '/sw.js': ['sw.js', 'text/javascript; charset=utf-8'],
  '/icon-192.png': ['icon-192.png', 'image/png'],
  '/icon-512.png': ['icon-512.png', 'image/png'],
  '/icon-maskable-512.png': ['icon-maskable-512.png', 'image/png'],
  '/apple-touch-icon.png': ['apple-touch-icon.png', 'image/png'],
};

export function createApp(opts = {}) {
  const cfg = {
    trustProxy: opts.trustProxy ?? process.env.TRUST_PROXY === '1',
    maxRooms: opts.maxRooms ?? num(process.env.MAX_ROOMS, 1000),
    maxClients: opts.maxClients ?? num(process.env.MAX_CLIENTS_PER_ROOM, 10),
    maxHistory: opts.maxHistory ?? num(process.env.MAX_HISTORY, 2000),
    createPerHour: opts.createPerHour ?? num(process.env.CREATE_PER_HOUR, 20),
    // Grace period for reconnecting: an empty room, an absent host, or an absent guest.
    graceMs: opts.graceMs ?? num(process.env.ROOM_GRACE_SECONDS, 60) * 1000,
    // A room nobody ever entered is removed after this long.
    unclaimedMs: opts.unclaimedMs ?? num(process.env.ROOM_UNCLAIMED_MINUTES, 10) * 60_000,
    roomFileBytes: opts.roomFileBytes ?? num(process.env.ROOM_FILE_MB, 50) * MB,
    totalFileBytes: opts.totalFileBytes ?? num(process.env.MAX_TOTAL_FILE_MB, 200) * MB,
  };

  const store = new Store({
    maxHistory: cfg.maxHistory,
    roomFileBytes: cfg.roomFileBytes,
    totalFileBytes: cfg.totalFileBytes,
  });
  const limiter = new RateLimiter();
  const rooms = new Map(); // roomId -> Set<ws> of people who are inside
  const pending = new Map(); // roomId -> Set<ws> of people waiting for the host's permission
  const ipConnections = new Map(); // ip -> open websocket count
  let nextConnId = 1;

  const staticCache = new Map();
  for (const [route, [file, type]] of Object.entries(STATIC_FILES)) {
    staticCache.set(route, { body: fs.readFileSync(path.join(PUBLIC_DIR, file)), type });
  }

  const ipOf = (req) => {
    if (cfg.trustProxy) {
      const fwd = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
      if (fwd) return fwd;
    }
    return req.socket.remoteAddress || 'unknown';
  };

  /* ---------------------------------------------------------------- HTTP */

  function setHeaders(req, res) {
    const host = String(req.headers.host || '').replace(/[^a-zA-Z0-9.:\-[\]]/g, '');
    res.setHeader(
      'Content-Security-Policy',
      [
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' blob:",
        "manifest-src 'self'",
        "worker-src 'self'",
        `connect-src 'self' ws://${host} wss://${host}`,
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
      ].join('; '),
    );
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), interest-cohort=()');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Cache-Control', 'no-store');
    const proto = cfg.trustProxy ? req.headers['x-forwarded-proto'] : req.socket.encrypted ? 'https' : '';
    if (proto === 'https') res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }

  function json(res, status, obj) {
    const body = JSON.stringify(obj);
    res.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': Buffer.byteLength(body),
    });
    res.end(body);
  }

  const httpError = (status, message) => Object.assign(new Error(message), { status });

  function readJson(req, limit = 4096) {
    return new Promise((resolve, reject) => {
      if (!String(req.headers['content-type'] || '').toLowerCase().startsWith('application/json')) {
        reject(httpError(415, 'content-type must be application/json'));
        return;
      }
      let size = 0;
      const chunks = [];
      req.on('data', (c) => {
        size += c.length;
        if (size > limit) {
          reject(httpError(413, 'request too large'));
          req.destroy();
          return;
        }
        chunks.push(c);
      });
      req.on('end', () => {
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
        } catch {
          reject(httpError(400, 'invalid json'));
        }
      });
      req.on('error', reject);
    });
  }

  async function createRoom(req, res) {
    const ip = ipOf(req);
    if (!limiter.take(`create:${ip}`, cfg.createPerHour, 3_600_000)) throw httpError(429, 'too many rooms created, try again later');
    if (store.count() >= cfg.maxRooms) throw httpError(503, 'this server has reached its room limit');

    const b = await readJson(req);
    const iterations = Number(b?.iterations);
    if (!isB64u(b?.salt, 22) || !isB64u(b?.auth, 43) || !isB64u(b?.hostToken, 43)) throw httpError(400, 'invalid request');
    if (!Number.isInteger(iterations) || iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) throw httpError(400, 'invalid iteration count');

    const id = crypto.randomBytes(16).toString('base64url'); // 128-bit, unguessable
    store.create({
      id,
      v: 2,
      salt: b.salt,
      iterations,
      authHash: sha256hex(b.auth),
      hostHash: sha256hex(b.hostToken),
      createdAt: Date.now(),
    });
    armExpiry(id, cfg.unclaimedMs);
    json(res, 201, { id });
  }

  function lookupRoom(req, res, id) {
    if (!limiter.take(`lookup:${ipOf(req)}`, 60, 60_000)) throw httpError(429, 'too many requests');
    const meta = store.readMeta(id);
    if (!meta) throw httpError(404, 'room not found');
    json(res, 200, { salt: meta.salt, iterations: meta.iterations });
  }

  function deleteRoomHttp(req, res, id) {
    const ip = ipOf(req);
    if (limiter.count(`hostfail:${ip}`, 600_000) >= 10) throw httpError(429, 'too many attempts');
    const meta = store.readMeta(id);
    if (!meta) throw httpError(404, 'room not found');
    const token = req.headers['x-host-token'];
    if (!isB64u(token, 43) || !matchesHash(token, meta.hostHash)) {
      limiter.add(`hostfail:${ip}`, 600_000);
      throw httpError(403, 'not the host of this room');
    }
    destroyRoom(id, 'host_deleted');
    json(res, 200, { deleted: true });
  }

  async function route(req, res) {
    setHeaders(req, res);
    let pathname;
    try {
      pathname = new URL(req.url, 'http://localhost').pathname;
    } catch {
      throw httpError(400, 'bad url');
    }
    const method = req.method;

    if (pathname === '/healthz') return json(res, 200, { ok: true });

    const isPage = /^\/r\/[^/]+\/?$/.test(pathname);
    if (isPage || staticCache.has(pathname)) {
      if (method !== 'GET' && method !== 'HEAD') throw httpError(405, 'method not allowed');
      const asset = staticCache.get(isPage ? '/' : pathname);
      res.writeHead(200, {
        'Content-Type': asset.type,
        'Content-Length': asset.body.length,
        'Cache-Control': 'no-cache',
      });
      res.end(method === 'HEAD' ? undefined : asset.body);
      return;
    }

    if (pathname === '/api/rooms') {
      if (method !== 'POST') throw httpError(405, 'method not allowed');
      return createRoom(req, res);
    }

    const m = pathname.match(/^\/api\/rooms\/([A-Za-z0-9_-]{22})$/);
    if (m) {
      if (method === 'GET') return lookupRoom(req, res, m[1]);
      if (method === 'DELETE') return deleteRoomHttp(req, res, m[1]);
      throw httpError(405, 'method not allowed');
    }

    throw httpError(404, 'not found');
  }

  const server = http.createServer(async (req, res) => {
    try {
      await route(req, res);
    } catch (e) {
      if (res.headersSent) return res.destroy();
      if (e.status) return json(res, e.status, { error: e.message });
      console.error('Unhandled error:', e.message);
      json(res, 500, { error: 'internal error' });
    }
  });

  /* ------------------------------------------------------------- helpers */

  const send = (ws, obj) => ws.send(JSON.stringify(obj));
  const hasHost = (set) => {
    for (const w of set) if (w.isHost) return true;
    return false;
  };

  function broadcast(roomId, obj, except) {
    const set = rooms.get(roomId);
    if (!set) return;
    const text = JSON.stringify(obj);
    for (const ws of set) if (ws !== except) ws.send(text);
  }

  function sendHosts(roomId, obj) {
    const set = rooms.get(roomId);
    if (!set) return;
    const text = JSON.stringify(obj);
    for (const ws of set) if (ws.isHost) ws.send(text);
  }

  const pendingList = (roomId) => [...(pending.get(roomId) ?? [])].map((w) => ({ c: w.id, hello: w.hello }));

  /* ------------------------------------------------------- room lifetime */
  // A room with nobody in it, or without its host, is erased once a timer runs out.

  const expiryTimers = new Map(); // empty room
  const hostAwayTimers = new Map(); // host gone

  function cancelExpiry(id) {
    const t = expiryTimers.get(id);
    if (t) clearTimeout(t);
    expiryTimers.delete(id);
  }

  function armExpiry(id, ms) {
    cancelExpiry(id);
    const t = setTimeout(() => {
      expiryTimers.delete(id);
      if (!rooms.has(id)) destroyRoom(id, 'host_left');
    }, ms);
    t.unref();
    expiryTimers.set(id, t);
  }

  function cancelHostAway(id) {
    const t = hostAwayTimers.get(id);
    if (t) clearTimeout(t);
    hostAwayTimers.delete(id);
  }

  function armHostAway(id) {
    cancelHostAway(id);
    const t = setTimeout(() => {
      hostAwayTimers.delete(id);
      const set = rooms.get(id);
      if (!set || !hasHost(set)) destroyRoom(id, 'host_left');
    }, cfg.graceMs);
    t.unref();
    hostAwayTimers.set(id, t);
  }

  /** Erase a room for good and tell everyone inside (and everyone waiting outside). */
  function destroyRoom(id, reason = 'host_deleted') {
    cancelExpiry(id);
    cancelHostAway(id);
    const text = JSON.stringify({ t: 'deleted', reason });
    const inside = rooms.get(id);
    const waiting = pending.get(id);
    rooms.delete(id);
    pending.delete(id);
    for (const set of [inside, waiting]) {
      if (!set) continue;
      for (const ws of set) {
        ws.send(text);
        ws.close(4000, 'room ended');
      }
    }
    store.delete(id);
  }

  /* ----------------------------------------------------------- WebSocket */

  function failJoin(ws, code) {
    send(ws, { t: 'error', code });
    ws.close(4003, code);
  }

  function handleJoin(ws, msg) {
    if (ws.roomId || ws.pendingRoom) return;
    const { room, auth, hostToken, ticket, session, hello } = msg;
    if (!isValidId(room) || !isB64u(auth, 43) || !validHello(hello)) return failJoin(ws, 'bad_request');

    const window = 10 * 60_000;
    const failRoomKey = `fail:${ws.ip}:${room}`;
    const failIpKey = `fail:${ws.ip}`;
    if (limiter.count(failRoomKey, window) >= 8 || limiter.count(failIpKey, window) >= 40) return failJoin(ws, 'rate_limited');

    const data = store.open(room);
    if (!data) return failJoin(ws, 'not_found');
    if (!matchesHash(auth, data.meta.authHash)) {
      limiter.add(failRoomKey, window);
      limiter.add(failIpKey, window);
      return failJoin(ws, 'bad_credentials');
    }
    ws.hello = hello;

    // The host.
    if (isB64u(hostToken, 43) && matchesHash(hostToken, data.meta.hostHash)) {
      return admit(ws, room, data, { isHost: true });
    }

    // Guests need a personal invite ticket, in addition to the password.
    if (!isB64u(ticket, 22)) return failJoin(ws, 'ticket_required');
    const t = data.tickets.get(ticket);
    if (!t) return failJoin(ws, 'ticket_invalid');

    if (t.state === 'unused') return admit(ws, room, data, { ticket: t, issueSession: true }); // first entry
    const sessionOk = isB64u(session, 43) && t.sessionHash && matchesHash(session, t.sessionHash);
    if (sessionOk && t.state !== 'left') return admit(ws, room, data, { ticket: t, resume: true }); // reconnecting
    if (!limiter.take(`knock:${room}:${ticket}`, 6, 600_000)) return failJoin(ws, 'rate_limited');
    return knock(ws, room, t); // coming back: needs the host's permission
  }

  function knock(ws, roomId, ticket) {
    const set = pending.get(roomId) ?? new Set();
    if (set.size >= MAX_KNOCKS) return failJoin(ws, 'rate_limited');
    clearTimeout(ws.joinTimer);
    ws.pendingRoom = roomId;
    ws.ticket = ticket;
    ws.isHost = false;
    set.add(ws);
    pending.set(roomId, set);
    ws.pendingTimer = setTimeout(() => {
      send(ws, { t: 'error', code: 'no_response' });
      ws.close(4006, 'no response');
    }, KNOCK_TIMEOUT_MS);
    ws.pendingTimer.unref();
    send(ws, { t: 'pending' });
    sendHosts(roomId, { t: 'knock', c: ws.id, hello: ws.hello });
  }

  /** Let a connection in. */
  function admit(ws, roomId, data, { isHost = false, ticket = null, resume = false, issueSession = false }) {
    let set = rooms.get(roomId);
    if (!set) {
      set = new Set();
      rooms.set(roomId, set);
    }

    // The same person reconnecting replaces their earlier (probably dead) connection.
    let replaces;
    if (ticket?.conn && ticket.conn !== ws) {
      const old = ticket.conn;
      replaces = old.id;
      set.delete(old);
      old.roomId = null;
      ticket.conn = null;
      send(old, { t: 'error', code: 'replaced' });
      old.close(4004, 'replaced');
    }
    if (set.size >= cfg.maxClients) return failJoin(ws, 'room_full');

    clearTimeout(ws.joinTimer);
    clearTimeout(ws.pendingTimer);
    ws.pendingRoom = null;
    ws.roomId = roomId;
    ws.uploadRoom = roomId;
    ws.isHost = isHost;
    ws.ticket = ticket;
    cancelExpiry(roomId);
    if (isHost) cancelHostAway(roomId);

    let newSession = null;
    if (ticket) {
      clearTimeout(ticket.timer);
      ticket.state = 'active';
      ticket.conn = ws;
      if (issueSession) {
        newSession = crypto.randomBytes(32).toString('base64url');
        ticket.sessionHash = sha256hex(newSession);
      }
    }

    const peers = [...set].map((p) => ({ c: p.id, hello: p.hello, h: p.isHost ? 1 : 0 }));
    const hostAway = !isHost && !hasHost(set);
    set.add(ws);

    send(ws, {
      t: 'ready',
      history: data.messages,
      online: set.size,
      max: cfg.maxClients,
      isHost,
      you: ws.id,
      peers,
      session: newSession,
      hostAway,
      knocks: isHost ? pendingList(roomId) : undefined,
    });
    broadcast(roomId, { t: 'joined', c: ws.id, hello: ws.hello, host: isHost ? 1 : 0, back: resume ? 1 : 0, replaces, online: set.size }, ws);
  }

  /** A connection left (or dropped). `explicit` means they pressed Leave. */
  function onGone(ws, { explicit = false } = {}) {
    const id = ws.roomId;
    if (!id) return;
    const set = rooms.get(id);
    if (!set || !set.delete(ws)) return;
    ws.roomId = null;
    broadcast(id, { t: 'left', c: ws.id, online: set.size });

    const t = ws.ticket;
    if (t && t.conn === ws) {
      t.conn = null;
      clearTimeout(t.timer);
      if (explicit) {
        t.state = 'left';
        t.sessionHash = null;
      } else {
        // Dropped connection: they may come straight back for a short while.
        t.state = 'away';
        t.timer = setTimeout(() => {
          if (t.state === 'away') {
            t.state = 'left';
            t.sessionHash = null;
          }
        }, cfg.graceMs);
        t.timer.unref();
      }
    }

    if (ws.isHost) {
      if (explicit) return destroyRoom(id, 'host_left'); // the host leaving ends the room
      if (!hasHost(set)) {
        broadcast(id, { t: 'host_away' });
        armHostAway(id);
      }
    }
    if (set.size === 0) {
      rooms.delete(id);
      armExpiry(id, cfg.graceMs); // erased unless someone comes back in time
    }
  }

  function decide(ws, msg, allow) {
    if (!ws.isHost || !ws.roomId) return;
    const target = [...(pending.get(ws.roomId) ?? [])].find((w) => w.id === msg.c);
    if (!target) return;
    const data = store.open(ws.roomId);
    pending.get(ws.roomId).delete(target);
    sendHosts(ws.roomId, { t: 'knock_done', c: target.id });
    if (!data) return;
    if (allow) {
      admit(target, ws.roomId, data, { ticket: target.ticket, issueSession: true });
      if (!target.roomId) send(ws, { t: 'error', code: 'room_full' }); // admit() refused: room is full
    } else {
      clearTimeout(target.pendingTimer);
      target.pendingRoom = null;
      send(target, { t: 'denied' });
      target.close(4005, 'denied');
    }
  }

  function handleMessage(ws, msg) {
    if (!ws.roomId) return;
    const { iv, ct } = msg;
    if (!isB64u(iv, 16) || typeof ct !== 'string' || ct.length < 22 || ct.length > MAX_CIPHERTEXT_CHARS || !B64U.test(ct)) {
      return send(ws, { t: 'error', code: 'bad_message' });
    }
    const stored = store.append(ws.roomId, { iv, ct });
    if (stored) broadcast(ws.roomId, { t: 'msg', m: stored });
  }

  function handleFileChunk(ws, msg) {
    if (!ws.roomId) return;
    const { f, i, n, iv, ct } = msg;
    if (
      !isB64u(f, 16) || !Number.isInteger(n) || n < 1 || n > MAX_CHUNKS || !Number.isInteger(i) || i < 0 || i >= n ||
      !isB64u(iv, 16) || typeof ct !== 'string' || ct.length < 22 || ct.length > MAX_CHUNK_CT_CHARS || !B64U.test(ct)
    ) {
      return send(ws, { t: 'error', code: 'bad_file', f });
    }
    const result = store.putChunk(ws.roomId, { f, i, n, iv, ct, owner: ws.id });
    if (result === 'full') return send(ws, { t: 'error', code: 'storage_full', f });
    if (result === 'bad' || result === 'gone') return send(ws, { t: 'error', code: 'bad_file', f });
    if (result === 'dup') return;
    (ws.uploads ??= new Set()).add(f);
    send(ws, { t: 'fack', f, i });
    if (result === 'done') {
      ws.uploads.delete(f);
      send(ws, { t: 'fdone', f });
    }
  }

  async function streamFile(ws, fid) {
    const roomId = ws.roomId;
    if (!roomId || !isB64u(fid, 16)) return;
    if (!limiter.take(`fget:${ws.id}`, 30, 60_000)) return send(ws, { t: 'error', code: 'rate_limited' });
    const file = store.getFile(roomId, fid);
    if (!file || !file.complete) return send(ws, { t: 'fmissing', f: fid });
    for (let i = 0; i < file.n; i++) {
      if (ws.readyState !== READY.OPEN || ws.roomId !== roomId) return;
      const c = file.chunks[i];
      if (!c) return;
      ws.send(JSON.stringify({ t: 'fchunk', f: fid, i, n: file.n, iv: c.iv, ct: c.ct }));
      if (ws.socket.writableNeedDrain) {
        await new Promise((resolve) => {
          ws.socket.once('drain', resolve);
          ws.socket.once('close', resolve);
        });
      }
    }
  }

  function newTicket(ws) {
    if (!ws.isHost || !ws.roomId) return;
    const data = store.open(ws.roomId);
    if (!data) return;
    if (data.tickets.size >= MAX_TICKETS) return send(ws, { t: 'error', code: 'too_many_invites' });
    const id = crypto.randomBytes(16).toString('base64url');
    data.tickets.set(id, { state: 'unused', sessionHash: null, conn: null, timer: null });
    send(ws, { t: 'ticket', id });
  }

  function onConnection(ws, ip) {
    ws.id = nextConnId++;
    ws.ip = ip;
    ws.roomId = null;
    ws.pendingRoom = null;
    ws.isHost = false;
    ws.ticket = null;
    ws.hello = null;
    ws.alive = true;
    ws.uploads = new Set();
    ws.uploadRoom = null;
    ws.joinTimer = setTimeout(() => ws.close(4001, 'join timeout'), 10_000);

    ws.on('pong', () => {
      ws.alive = true;
    });

    ws.on('message', (text) => {
      if (!limiter.take(`wsraw:${ws.id}`, 800, 10_000)) return ws.terminate(); // flooding
      let msg;
      try {
        msg = JSON.parse(text);
      } catch {
        return;
      }
      if (!msg || typeof msg !== 'object') return;

      const bulk = msg.t === 'fchunk' || msg.t === 'fget';
      const allowed = bulk ? limiter.take(`wsf:${ws.id}`, 400, 30_000) : limiter.take(`ws:${ws.id}`, 30, 10_000);
      if (!allowed) return send(ws, { t: 'error', code: 'rate_limited' });

      switch (msg.t) {
        case 'join':
          return handleJoin(ws, msg);
        case 'msg':
          return handleMessage(ws, msg);
        case 'fchunk':
          return handleFileChunk(ws, msg);
        case 'fget':
          return void streamFile(ws, msg.f).catch(() => {});
        case 'newticket':
          return newTicket(ws);
        case 'admit':
          return decide(ws, msg, true);
        case 'deny':
          return decide(ws, msg, false);
        case 'leave':
          if (ws.roomId) onGone(ws, { explicit: true });
          return ws.close(1000, 'left');
        case 'delete':
          if (!ws.roomId) return;
          if (!ws.isHost) return send(ws, { t: 'error', code: 'forbidden' });
          return destroyRoom(ws.roomId, 'host_deleted');
        default:
          return;
      }
    });

    ws.on('close', () => {
      clearTimeout(ws.joinTimer);
      clearTimeout(ws.pendingTimer);
      const left = (ipConnections.get(ip) ?? 1) - 1;
      if (left > 0) ipConnections.set(ip, left);
      else ipConnections.delete(ip);

      if (ws.pendingRoom) {
        pending.get(ws.pendingRoom)?.delete(ws);
        sendHosts(ws.pendingRoom, { t: 'knock_done', c: ws.id });
      }
      // An upload that never finished must not keep eating the room's space.
      if (ws.uploadRoom) for (const f of ws.uploads) store.dropFile(ws.uploadRoom, f);
      onGone(ws);
    });
  }

  server.on('upgrade', (req, socket, head) => {
    socket.on('error', () => socket.destroy());

    let pathname;
    try {
      pathname = new URL(req.url, 'http://localhost').pathname;
    } catch {
      return socket.destroy();
    }
    if (pathname !== '/ws') return socket.end('HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');

    // Block cross-site WebSocket hijacking: browsers always send Origin.
    const origin = req.headers.origin;
    if (origin) {
      let originHost = null;
      try {
        originHost = new URL(origin).host;
      } catch {
        /* handled below */
      }
      if (originHost !== req.headers.host) {
        return socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
      }
    }

    const ip = ipOf(req);
    if ((ipConnections.get(ip) ?? 0) >= MAX_CONNECTIONS_PER_IP) {
      return socket.end('HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    }

    const ws = acceptUpgrade(req, socket, head, { maxPayload: MAX_WS_PAYLOAD });
    if (!ws) return;
    ipConnections.set(ip, (ipConnections.get(ip) ?? 0) + 1);
    onConnection(ws, ip);
  });

  /* ------------------------------------------------------- housekeeping */

  const heartbeat = setInterval(() => {
    for (const set of [...rooms.values(), ...pending.values()]) {
      for (const ws of set) {
        if (!ws.alive) {
          ws.terminate();
          continue;
        }
        ws.alive = false;
        ws.ping();
      }
    }
  }, 30_000);
  heartbeat.unref();

  return {
    server,
    store,
    config: cfg,
    listen(port, host) {
      return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, host, () => resolve(server.address()));
      });
    },
    async close() {
      clearInterval(heartbeat);
      for (const t of expiryTimers.values()) clearTimeout(t);
      for (const t of hostAwayTimers.values()) clearTimeout(t);
      limiter.stop();
      for (const set of [...rooms.values(), ...pending.values()]) for (const ws of set) ws.terminate();
      await new Promise((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections?.();
      });
    },
  };
}

/* ------------------------------------------------------------------ main */

const isMain = process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isMain) {
  const port = num(process.env.PORT, 3000);
  const host = process.env.HOST || '0.0.0.0';
  const app = createApp();
  app.listen(port, host).then(() => {
    console.log(`CipherRoom listening on http://${host === '0.0.0.0' ? 'localhost' : host}:${port}`);
    console.log('Rooms live in memory only and are erased when the host leaves or everyone has left.');
    console.log('No access logs are written, by design. Serve it over HTTPS in production.');
  }).catch((e) => {
    console.error(
      e.code === 'EADDRINUSE'
        ? `Port ${port} is already in use. CipherRoom may already be running in another window. Close it and try again.`
        : `Could not start: ${e.message}`,
    );
    process.exit(1);
  });
  const shutdown = () => app.close().then(() => process.exit(0));
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
